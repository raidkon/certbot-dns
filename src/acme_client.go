package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/resolver"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/libdns/libdns"
	fastdns "github.com/nf404/libdns-fastdns"
)

// certLiveSymlinkName — имя symlink в output_dir на актуальный каталог выпуска (YYYY-MM-DD).
const certLiveSymlinkName = "live"

type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string {
	return u.email
}

func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.registration
}

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type fastDNSsolver struct {
	zone   string
	client *fastdns.Provider

	propagationTimeout  time.Duration
	propagationInterval time.Duration

	// afterTXTCreate вызывается после успешного AppendRecords (для чекпоинта возобновления выпуска).
	afterTXTCreate func(challengeKey, recordID string)

	mu  sync.Mutex
	ids map[string]string
}

func (s *fastDNSsolver) Timeout() (timeout, interval time.Duration) {
	return s.propagationTimeout, s.propagationInterval
}

// Sequential — lego вызывает последовательный DNS-01 (challenge/resolver.sequentialSolve):
// один challenge за раз: PreSolve → Solve → CleanUp → пауза → следующий.
// У FastDNS два параллельных AppendRecords на одно имя (_acme-challenge для *.zone + zone)
// часто дают ошибку без текста; последовательный режим оставляет в зоне одну TXT за раз.
func (s *fastDNSsolver) Sequential() time.Duration {
	if s.propagationInterval > 0 {
		return s.propagationInterval
	}
	return 5 * time.Second
}

func normalizeFQDN(fqdn string) string {
	return strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
}

func recordNameForZone(effectiveFQDN, zone string) string {
	effectiveFQDN = normalizeFQDN(effectiveFQDN)
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if zone == "" {
		return effectiveFQDN
	}
	suf := "." + zone
	if strings.HasSuffix(effectiveFQDN, suf) {
		return strings.TrimSuffix(effectiveFQDN, suf)
	}
	return effectiveFQDN
}

func (s *fastDNSsolver) challengeKey(domain, keyAuth string) string {
	return normalizeFQDN(dns01.GetChallengeInfo(domain, keyAuth).EffectiveFQDN)
}

// restoreTXTRecordIDs подставляет ID записей из чекпоинта, чтобы Present не дублировал TXT при возобновлении.
func (s *fastDNSsolver) restoreTXTRecordIDs(from map[string]string) {
	if len(from) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ids == nil {
		s.ids = make(map[string]string)
	}
	for k, id := range from {
		if k != "" && id != "" {
			s.ids[k] = id
		}
	}
}

func (s *fastDNSsolver) normalizeTXTRecordName(recName string) string {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(recName)), ".")
	z := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.zone), "."))
	if z != "" && strings.HasSuffix(n, "."+z) {
		n = strings.TrimSuffix(n, "."+z)
	}
	return n
}

func fastDNSHTTPRetriable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "eof") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "tls: bad record mac") ||
		strings.Contains(s, "502 bad gateway") ||
		strings.Contains(s, "503 service") ||
		strings.Contains(s, "504 gateway") ||
		strings.Contains(s, "429 too many")
}

// fastDNSRetryWithValue повторяет вызов API FastDNS при обрывах соединения (EOF, таймауты).
func fastDNSRetryWithValue[T any](op string, fn func() (T, error)) (T, error) {
	var zero T
	delays := []time.Duration{0, 400 * time.Millisecond, 1 * time.Second, 2 * time.Second, 4 * time.Second}
	var lastErr error
	for attempt := range delays {
		if delays[attempt] > 0 {
			time.Sleep(delays[attempt])
		}
		v, err := fn()
		if err == nil {
			if attempt > 0 {
				slog.Info("FastDNS: успех после повтора", "op", op, "attempt", attempt+1)
			}
			return v, nil
		}
		lastErr = err
		if !fastDNSHTTPRetriable(err) || attempt == len(delays)-1 {
			return zero, err
		}
		slog.Warn("FastDNS: временная ошибка, повтор", "op", op, "attempt", attempt+1, "err", err)
	}
	return zero, lastErr
}

// purgeConflictingTXT удаляет в зоне все TXT с тем же относительным именем, что и для DNS-01.
// В панели часто остаются старые _acme-challenge от сорванных выпусков — FastDNS тогда отвечает
// на AppendRecords пустым message (лимит «одна запись на имя» или отказ дубля).
func (s *fastDNSsolver) purgeConflictingTXT(ctx context.Context, relName string) (removed int, err error) {
	recs, err := fastDNSRetryWithValue("GetRecords(purge)", func() ([]libdns.Record, error) {
		return s.client.GetRecords(ctx, s.zone)
	})
	if err != nil {
		return 0, err
	}
	target := s.normalizeTXTRecordName(relName)
	var deletedIDs []string
	for _, r := range recs {
		if !strings.EqualFold(strings.TrimSpace(r.Type), "TXT") {
			continue
		}
		if strings.TrimSpace(r.ID) == "" {
			continue
		}
		if s.normalizeTXTRecordName(r.Name) != target {
			continue
		}
		_, delErr := fastDNSRetryWithValue(fmt.Sprintf("DeleteRecords(purge) id=%s", r.ID), func() (struct{}, error) {
			_, e := s.client.DeleteRecords(ctx, s.zone, []libdns.Record{{ID: r.ID}})
			return struct{}{}, e
		})
		if delErr != nil {
			return removed, fmt.Errorf("DeleteRecords TXT id=%s name=%q: %w", r.ID, r.Name, delErr)
		}
		deletedIDs = append(deletedIDs, r.ID)
		removed++
		slog.Debug("purge: удалена TXT перед ACME Present", "zone", s.zone, "record_id", r.ID, "name", r.Name)
	}
	if len(deletedIDs) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	for chKey, id := range s.ids {
		for _, did := range deletedIDs {
			if id == did {
				delete(s.ids, chKey)
				break
			}
		}
	}
	s.mu.Unlock()
	slog.Info("очищены старые TXT для DNS-01", "zone", s.zone, "relative_name", relName, "removed", removed)
	return removed, nil
}

func (s *fastDNSsolver) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	name := recordNameForZone(info.EffectiveFQDN, s.zone)
	ctx := context.Background()

	if _, err := s.purgeConflictingTXT(ctx, name); err != nil {
		return fmt.Errorf("очистка TXT перед Present: %w", err)
	}

	k := s.challengeKey(domain, keyAuth)
	s.mu.Lock()
	already := s.ids[k] != ""
	s.mu.Unlock()
	if already {
		slog.Debug("DNS-01 Present: пропуск (запись уже в памяти/чекпоинте)", "challenge_key", k, "acme_identifier", domain)
		return nil
	}

	slog.Debug("DNS-01 Present",
		"acme_identifier", domain,
		"txt_fqdn", info.EffectiveFQDN,
		"txt_name_in_zone", name,
		"fastdns_zone", s.zone,
		"ttl_sec", dns01.DefaultTTL,
	)

	rec := libdns.Record{
		Type:  "TXT",
		Name:  name,
		Value: info.Value,
		TTL:   time.Duration(dns01.DefaultTTL) * time.Second,
	}

	added, err := fastDNSRetryWithValue("AppendRecords", func() ([]libdns.Record, error) {
		return s.client.AppendRecords(ctx, s.zone, []libdns.Record{rec})
	})
	if err != nil {
		if strings.TrimSpace(err.Error()) == "" {
			slog.Warn("FastDNS AppendRecords: пустое message в ошибке API (лимиты зоны, дубликат имени или квота)",
				"txt_name_in_zone", name, "fastdns_zone", s.zone)
			return fmt.Errorf("fastdns AppendRecords (name=%q zone=%q): пустой ответ API", name, s.zone)
		}
		return fmt.Errorf("fastdns AppendRecords (name=%q zone=%q): %w", name, s.zone, err)
	}
	if len(added) == 0 || added[0].ID == "" {
		return errors.New("fastdns: пустой ответ AppendRecords (нет ID записи)")
	}

	recID := added[0].ID
	s.mu.Lock()
	if s.ids == nil {
		s.ids = make(map[string]string)
	}
	s.ids[k] = recID
	cb := s.afterTXTCreate
	s.mu.Unlock()

	if cb != nil {
		cb(k, recID)
	}

	slog.Info("DNS TXT создан в FastDNS", "zone", s.zone, "record_id", recID, "name", name, "acme_identifier", domain)

	return nil
}

func (s *fastDNSsolver) CleanUp(domain, token, keyAuth string) error {
	k := s.challengeKey(domain, keyAuth)
	s.mu.Lock()
	id := s.ids[k]
	delete(s.ids, k)
	s.mu.Unlock()
	if id == "" {
		slog.Debug("DNS-01 CleanUp: запись уже удалена или не отслеживалась", "acme_identifier", domain)
		return nil
	}

	ctx := context.Background()
	slog.Debug("DNS-01 CleanUp", "zone", s.zone, "record_id", id, "acme_identifier", domain)
	_, err := fastDNSRetryWithValue("DeleteRecords(cleanup)", func() (struct{}, error) {
		_, e := s.client.DeleteRecords(ctx, s.zone, []libdns.Record{{ID: id}})
		return struct{}{}, e
	})
	if err != nil {
		return fmt.Errorf("fastdns DeleteRecords: %w", err)
	}
	slog.Info("DNS TXT удалён из FastDNS", "zone", s.zone, "record_id", id)
	return nil
}

var _ challenge.Provider = (*fastDNSsolver)(nil)
var _ challenge.ProviderTimeout = (*fastDNSsolver)(nil)
// dns01.Challenge проверяет провайдер на sequential — см. fastDNSsolver.Sequential.

func verifyFastDNSZone(ctx context.Context, fd *fastdns.Provider, zone string) error {
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	recs, err := fastDNSRetryWithValue("GetRecords(verify zone)", func() ([]libdns.Record, error) {
		return fd.GetRecords(ctx, zone)
	})
	if err != nil {
		return fmt.Errorf("зона %q недоступна через FastDNS API (проверьте токен и имя зоны): %w", zone, err)
	}
	slog.Debug("FastDNS GetRecords успешно", "zone", zone, "records_count", len(recs))
	return nil
}

func loadOrCreateAccountKey(dir string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(dir, "account.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("не удалось разобрать PEM в %s", path)
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		return k, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	var buf strings.Builder
	_ = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func loadRegistration(dir string) (*registration.Resource, error) {
	path := filepath.Join(dir, "registration.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var res registration.Resource
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func saveRegistration(dir string, res *registration.Resource) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "registration.json"), raw, 0o600)
}

func registerOrLoad(client *lego.Client, stateDir string, user *acmeUser) error {
	if user.registration != nil {
		return nil
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		var pd *acme.ProblemDetails
		if errors.As(err, &pd) && pd != nil && pd.HTTPStatus == http.StatusConflict {
			var errRes error
			reg, errRes = client.Registration.ResolveAccountByKey()
			if errRes != nil {
				return fmt.Errorf("ACME Register (409): %w; ResolveAccountByKey: %v", err, errRes)
			}
		} else {
			return fmt.Errorf("ACME Register: %w", err)
		}
	}
	user.registration = reg
	return saveRegistration(stateDir, reg)
}

func writePEM(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), data, 0o600)
}

// certBundleVersionDir возвращает имя каталога YYYY-MM-DD по NotBefore листового сертификата (UTC).
func certBundleVersionDir(fullchain []byte) (string, error) {
	var data = fullchain
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return "", errors.New("fullchain: нет блока CERTIFICATE")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		return cert.NotBefore.UTC().Format("2006-01-02"), nil
	}
}

func updateLiveSymlink(outDir, version string) error {
	link := filepath.Join(outDir, certLiveSymlinkName)
	if fi, err := os.Lstat(link); err == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s существует и не symlink — удалите или переименуйте вручную", link)
		}
		if err := os.Remove(link); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(version, link)
}

// writeCertBundle пишет fullchain/privkey[/issuer] в outDir/YYYY-MM-DD/ и обновляет symlink outDir/live.
func writeCertBundle(outDir string, fullchain, privkey, issuer []byte) error {
	version, err := certBundleVersionDir(fullchain)
	if err != nil {
		version = time.Now().UTC().Format("2006-01-02")
		slog.Debug("каталог версии: fallback на дату UTC", "err", err, "version", version)
	}
	dest := filepath.Join(outDir, version)
	if err := writePEM(dest, "fullchain.pem", fullchain); err != nil {
		return err
	}
	if err := writePEM(dest, "privkey.pem", privkey); err != nil {
		return err
	}
	if len(issuer) > 0 {
		_ = writePEM(dest, "issuer.pem", issuer)
	}
	if err := updateLiveSymlink(outDir, version); err != nil {
		return err
	}
	slog.Debug("сертификаты записаны в каталог версии", "out_dir", outDir, "version_dir", version, "live", filepath.Join(outDir, certLiveSymlinkName))
	return nil
}

// resolveFullchainReadPath — путь к актуальному fullchain: live/fullchain.pem или legacy fullchain.pem в корне output_dir.
func resolveFullchainReadPath(outputDir string) string {
	live := filepath.Join(outputDir, certLiveSymlinkName, "fullchain.pem")
	if _, err := os.Stat(live); err == nil {
		return live
	}
	legacy := filepath.Join(outputDir, "fullchain.pem")
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return live
}

// resolvePrivkeyReadPath — аналогично для privkey.
func resolvePrivkeyReadPath(outputDir string) string {
	live := filepath.Join(outputDir, certLiveSymlinkName, "privkey.pem")
	if _, err := os.Stat(live); err == nil {
		return live
	}
	legacy := filepath.Join(outputDir, "privkey.pem")
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return live
}

func parseKeyType(s string) (certcrypto.KeyType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ec256", "p256":
		return certcrypto.EC256, nil
	case "ec384", "p384":
		return certcrypto.EC384, nil
	case "rsa2048", "2048":
		return certcrypto.RSA2048, nil
	case "rsa3072", "3072":
		return certcrypto.RSA3072, nil
	case "rsa4096", "4096":
		return certcrypto.RSA4096, nil
	case "rsa8192", "8192":
		return certcrypto.RSA8192, nil
	default:
		return "", fmt.Errorf("неизвестный key_type %q", s)
	}
}

// defaultPropagationResolvers — если в конфиге не указаны recursive_resolvers, не полагаемся на
// /etc/resolv.conf (127.0.0.53), иначе проверка «TXT уже в DNS» часто зависает или расходится с LE.
var defaultPropagationResolvers = []string{"8.8.8.8:53", "1.1.1.1:53"}

func effectivePropagationResolvers(cfg *Config) []string {
	var ns []string
	for _, s := range cfg.DNSChallenge.RecursiveResolvers {
		s = strings.TrimSpace(s)
		if s != "" {
			ns = append(ns, s)
		}
	}
	if len(ns) == 0 {
		return append([]string(nil), defaultPropagationResolvers...)
	}
	return ns
}

func buildDNSOpts(cfg *Config) ([]dns01.ChallengeOption, error) {
	ns := effectivePropagationResolvers(cfg)
	return []dns01.ChallengeOption{dns01.AddRecursiveNameservers(ns)}, nil
}

func obtainCertificate(
	cfg *Config,
	propTimeout, propInterval time.Duration,
	dnsOpts []dns01.ChallengeOption,
	exp ExpandedCert,
) error {
	slog.Info("Obtain: старт", "label", exp.Label, "san", exp.Domains, "acme_directory", cfg.ACME.Directory, "state_dir", cfg.ACME.StateDir)
	stateDir := cfg.ACME.StateDir
	accountKey, err := loadOrCreateAccountKey(stateDir)
	if err != nil {
		return fmt.Errorf("ключ ACME: %w", err)
	}
	slog.Debug("ключ ACME загружен или создан", "state_dir", stateDir)

	var reg *registration.Resource
	if r, err := loadRegistration(stateDir); err == nil {
		reg = r
		slog.Debug("найден registration.json", "state_dir", stateDir)
	} else {
		slog.Debug("registration.json отсутствует — будет Register", "state_dir", stateDir, "err", err)
	}

	user := &acmeUser{
		email:        cfg.ACME.Email,
		registration: reg,
		key:          accountKey,
	}

	kt, err := parseKeyType(exp.KeyType)
	if err != nil {
		return err
	}

	legoCfg := lego.NewConfig(user)
	if strings.EqualFold(strings.TrimSpace(cfg.ACME.Directory), "staging") {
		legoCfg.CADirURL = lego.LEDirectoryStaging
	}
	slog.Debug("lego конфиг ACME", "cadir_url", legoCfg.CADirURL, "staging", strings.EqualFold(strings.TrimSpace(cfg.ACME.Directory), "staging"))
	legoCfg.UserAgent = cfg.ACME.UserAgent
	legoCfg.Certificate.KeyType = kt

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return fmt.Errorf("lego client: %w", err)
	}
	slog.Debug("lego.NewClient (до регистрации)", "kid_empty", user.GetRegistration() == nil)

	fd := &fastdns.Provider{
		APIToken: cfg.FastDNS.APIToken,
		APIUrl:   cfg.FastDNS.APIURL,
	}

	if err := registerOrLoad(client, stateDir, user); err != nil {
		return err
	}
	regURI := ""
	if user.GetRegistration() != nil {
		regURI = user.GetRegistration().URI
	}
	slog.Debug("ACME регистрация/аккаунт готов", "registration_uri", regURI)

	kid := ""
	if user.GetRegistration() != nil {
		kid = user.GetRegistration().URI
	}
	core, err := api.New(legoCfg.HTTPClient, legoCfg.UserAgent, legoCfg.CADirURL, kid, user.GetPrivateKey())
	if err != nil {
		return fmt.Errorf("api.Core: %w", err)
	}

	solver := &fastDNSsolver{
		zone:                strings.TrimSuffix(strings.TrimSpace(exp.Zone), "."),
		client:              fd,
		propagationTimeout:  propTimeout,
		propagationInterval: propInterval,
	}

	sm := resolver.NewSolversManager(core)
	if err := sm.SetDNS01Provider(solver, dnsOpts...); err != nil {
		return fmt.Errorf("SetDNS01Provider: %w", err)
	}
	slog.Debug("DNS01 provider установлен", "solver_zone", solver.zone, "propagation_timeout", propTimeout, "propagation_interval", propInterval)

	prober := resolver.NewProber(sm)
	certOpts := certificate.CertifierOptions{
		KeyType:             legoCfg.Certificate.KeyType,
		Timeout:             legoCfg.Certificate.Timeout,
		OverallRequestLimit: legoCfg.Certificate.OverallRequestLimit,
		DisableCommonName:   legoCfg.Certificate.DisableCommonName,
	}

	slog.Info("выпуск сертификата ACME (чекпоинт .obtain-checkpoint.json)", "domains", exp.Domains, "bundle", true)
	if err := runObtainWithCheckpoint(core, prober, certOpts, solver, exp); err != nil {
		return fmt.Errorf("Obtain: %w", err)
	}
	slog.Debug("Obtain успешен", "out_dir", exp.OutputDir)
	return nil
}
