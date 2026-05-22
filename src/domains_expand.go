package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// ExpandedCert — один выпуск после разборки domains (зона и каталог выводятся автоматически).
type ExpandedCert struct {
	Label           string   // для логов
	Zone            string   // зона FastDNS в панели (обычно «домен.tld» — последние две метки apex)
	Domains         []string // список SAN в запросе к ACME
	OutputDir       string   // каталог выпуска: YYYY-MM-DD/*.pem и symlink live/
	KeyType         string
	RenewBeforeDays int
}

// fastDNSRootZone — имя зоны в FastVPS FastDNS: по умолчанию последние две метки FQDN (host.example.com → example.com).
// Для *.server.raidkon.com с apex server.raidkon.com → raidkon.com. Для многоуровневых ccTLD (co.uk) эвристика неточна.
func fastDNSRootZone(host string) string {
	host = normDomain(host)
	if host == "" {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func normDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// expandCertEntry превращает domains из одного [[certificates]] в несколько ExpandedCert по правилам:
//   - *.a.b → сертификат SAN: *.a.b и a.b (apex подставляется сам);
//   - имя на один уровень под этим apex (www.a.b) попадает в ту же группу, если в списке есть *.a.b;
//   - только c.d без подходящего *.… в списке → отдельный сертификат (зона FastDNS — fastDNSRootZone(c.d)).
func expandCertEntry(entry CertConfig, parentIdx int) ([]ExpandedCert, error) {
	raw := dedupePreserveOrder(entry.Domains)
	var norm []string
	for _, d := range raw {
		nd := normDomain(d)
		if nd == "" {
			return nil, fmt.Errorf("пустой элемент в domains")
		}
		if strings.Contains(nd, "*") && !strings.HasPrefix(nd, "*.") {
			return nil, fmt.Errorf("некорректное имя с '*': %q", d)
		}
		norm = append(norm, nd)
	}
	if len(norm) == 0 {
		return nil, fmt.Errorf("domains пуст (certificates[%d])", parentIdx)
	}

	type grp struct {
		apex    string
		domains map[string]struct{}
	}
	byApex := make(map[string]*grp)
	assigned := make(map[string]struct{})

	addToGroup := func(apex string, names ...string) {
		g := byApex[apex]
		if g == nil {
			g = &grp{apex: apex, domains: make(map[string]struct{})}
			byApex[apex] = g
		}
		for _, n := range names {
			n = normDomain(n)
			g.domains[n] = struct{}{}
			assigned[n] = struct{}{}
		}
	}

	for _, d := range norm {
		if strings.HasPrefix(d, "*.") {
			apex := strings.TrimPrefix(d, "*.")
			if apex == "" {
				return nil, fmt.Errorf("пустой apex у wildcard %q", d)
			}
			addToGroup(apex, "*."+apex, apex)
		}
	}

	// Явный apex в списке рядом с wildcard уже попал в группу; помечаем дубликат как assigned без новой группы
	for _, d := range norm {
		if strings.HasPrefix(d, "*.") {
			continue
		}
		if _, hasWC := byApex[d]; hasWC {
			assigned[d] = struct{}{}
		}
	}

	// Одиночная метка под *.apex (например www.example.com при *.example.com) — в ту же wildcard-группу
	for _, d := range norm {
		if strings.HasPrefix(d, "*.") {
			continue
		}
		if _, ok := assigned[d]; ok {
			continue
		}
		best := ""
		for apex := range byApex {
			if underOneLabelSubdomain(d, apex) && len(apex) > len(best) {
				best = apex
			}
		}
		if best != "" {
			byApex[best].domains[d] = struct{}{}
			assigned[d] = struct{}{}
		}
	}

	parentLabel := certLabel(entry, parentIdx)
	baseOut := filepath.Clean(entry.OutputDir)

	var out []ExpandedCert

	wcOrder := wildcardApexOrder(norm)
	for _, apex := range wcOrder {
		g := byApex[apex]
		if g == nil {
			continue
		}
		out = append(out, ExpandedCert{
			Label:           fmt.Sprintf("%s/%s", parentLabel, slugForApex(apex)),
			Zone:            fastDNSRootZone(apex),
			Domains:         sortedDomains(mapKeys(g.domains)),
			OutputDir:       filepath.Join(baseOut, "wc-"+slugForApex(apex)),
			KeyType:         entry.KeyType,
			RenewBeforeDays: entry.RenewBeforeDays,
		})
	}

	// Оставшиеся домены — по одному сертификату (нет подходящего *.apex в списке)
	for _, d := range norm {
		if strings.HasPrefix(d, "*.") {
			continue
		}
		if _, ok := assigned[d]; ok {
			continue
		}
		out = append(out, ExpandedCert{
			Label:           fmt.Sprintf("%s/%s", parentLabel, slugForApex(d)),
			Zone:            fastDNSRootZone(d),
			Domains:         []string{d},
			OutputDir:       filepath.Join(baseOut, "apex-"+slugForApex(d)),
			KeyType:         entry.KeyType,
			RenewBeforeDays: entry.RenewBeforeDays,
		})
	}

	return out, nil
}

func expandAllCerts(entries []CertConfig) ([]ExpandedCert, error) {
	var all []ExpandedCert
	for i := range entries {
		expanded, err := expandCertEntry(entries[i], i)
		if err != nil {
			return nil, fmt.Errorf("certificates[%d]: %w", i, err)
		}
		all = append(all, expanded...)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("после разбора domains не осталось ни одного сертификата")
	}
	return all, nil
}

func dedupePreserveOrder(domains []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, d := range domains {
		k := normDomain(d)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func wildcardApexOrder(norm []string) []string {
	var order []string
	seen := make(map[string]struct{})
	for _, d := range norm {
		if !strings.HasPrefix(d, "*.") {
			continue
		}
		apex := strings.TrimPrefix(d, "*.")
		if _, ok := seen[apex]; ok {
			continue
		}
		seen[apex] = struct{}{}
		order = append(order, apex)
	}
	return order
}

func sortedDomains(m []string) []string {
	s := append([]string(nil), m...)
	sort.Strings(s)
	return s
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func slugForApex(apex string) string {
	return strings.ReplaceAll(apex, ".", "-")
}

// underOneLabelSubdomain: d совпадает с apex или d = «одна метка».apex (например api.p1.example.org при apex p1.example.org).
func underOneLabelSubdomain(d, apex string) bool {
	d, apex = normDomain(d), normDomain(apex)
	if d == apex {
		return true
	}
	suf := "." + apex
	if !strings.HasSuffix(d, suf) {
		return false
	}
	pref := strings.TrimSuffix(d, suf)
	return pref != "" && !strings.Contains(pref, ".")
}
