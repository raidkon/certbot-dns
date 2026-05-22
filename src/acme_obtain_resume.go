package main

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/resolver"
	"github.com/go-acme/lego/v4/platform/wait"
	"golang.org/x/net/idna"
)

// Файл чекпоинта в каталоге output_dir выпуска: при обрыве процесс продолжит тот же заказ ACME.
const obtainCheckpointFile = ".obtain-checkpoint.json"

const obtainCheckpointVersion = 1

type obtainCheckpoint struct {
	Version       int               `json:"version"`
	UpdatedUTC    string            `json:"updated_utc"`
	Domains       []string          `json:"domains"`
	OrderURI      string            `json:"order_uri"`
	TXTRecordIDs  map[string]string `json:"txt_record_ids,omitempty"`
	PrivateKeyPEM string            `json:"private_key_pem,omitempty"`
}

func obtainCheckpointPath(outputDir string) string {
	return filepath.Join(outputDir, obtainCheckpointFile)
}

func loadObtainCheckpoint(outputDir string) (*obtainCheckpoint, error) {
	raw, err := os.ReadFile(obtainCheckpointPath(outputDir))
	if err != nil {
		return nil, err
	}
	var c obtainCheckpoint
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if c.Version != obtainCheckpointVersion {
		return nil, fmt.Errorf("версия чекпоинта %d не поддерживается", c.Version)
	}
	if c.TXTRecordIDs == nil {
		c.TXTRecordIDs = map[string]string{}
	}
	return &c, nil
}

func saveObtainCheckpoint(outputDir string, c *obtainCheckpoint) error {
	if c.TXTRecordIDs == nil {
		c.TXTRecordIDs = map[string]string{}
	}
	c.UpdatedUTC = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	p := obtainCheckpointPath(outputDir)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func removeObtainCheckpoint(outputDir string) error {
	err := os.Remove(obtainCheckpointPath(outputDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func domainsEqualObtain(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sanitizeObtainDomains(domains []string) ([]string, error) {
	var out []string
	for _, d := range domains {
		ascii, err := idna.ToASCII(strings.TrimSpace(d))
		if err != nil {
			return nil, fmt.Errorf("домен %q: punycode: %w", d, err)
		}
		out = append(out, ascii)
	}
	return out, nil
}

func attachCheckpointTXTHook(solver *fastDNSsolver, outputDir string) {
	var mu sync.Mutex
	solver.afterTXTCreate = func(challengeKey, recordID string) {
		mu.Lock()
		defer mu.Unlock()
		cp, err := loadObtainCheckpoint(outputDir)
		if err != nil {
			slog.Warn("чекпоинт: не удалось прочитать при сохранении TXT", "err", err)
			return
		}
		cp.TXTRecordIDs[challengeKey] = recordID
		if err := saveObtainCheckpoint(outputDir, cp); err != nil {
			slog.Warn("чекпоинт: не удалось записать id TXT", "err", err)
		}
	}
}

func fetchAuthorizationsSequential(core *api.Core, order acme.ExtendedOrder) ([]acme.Authorization, error) {
	var out []acme.Authorization
	for _, u := range order.Authorizations {
		a, err := core.Authorizations.Get(u)
		if err != nil {
			return nil, fmt.Errorf("authorization get %q: %w", u, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func authzAllValid(authz []acme.Authorization) bool {
	for _, a := range authz {
		if a.Status != acme.StatusValid {
			return false
		}
	}
	return true
}

func loadOrGeneratePrivateKey(cp *obtainCheckpoint, kt certcrypto.KeyType) (crypto.PrivateKey, error) {
	if strings.TrimSpace(cp.PrivateKeyPEM) != "" {
		return certcrypto.ParsePEMPrivateKey([]byte(cp.PrivateKeyPEM))
	}
	key, err := certcrypto.GeneratePrivateKey(kt)
	if err != nil {
		return nil, err
	}
	pemBytes := certcrypto.PEMEncode(key)
	cp.PrivateKeyPEM = string(pemBytes)
	return key, nil
}

func createCSRForOrder(domains []string, order acme.ExtendedOrder, priv crypto.PrivateKey, certOpts certificate.CertifierOptions) ([]byte, error) {
	commonName := ""
	if len(domains) > 0 && len(domains[0]) <= 64 && !certOpts.DisableCommonName {
		commonName = domains[0]
	}
	var san []string
	if commonName != "" {
		san = append(san, commonName)
	}
	for _, id := range order.Identifiers {
		if id.Value != commonName {
			san = append(san, id.Value)
		}
	}
	return certcrypto.CreateCSR(priv, certcrypto.CSROptions{
		Domain: commonName,
		SAN:    san,
	})
}

func downloadAndWriteCert(
	core *api.Core,
	order acme.ExtendedOrder,
	cp *obtainCheckpoint,
	outDir string,
	bundle bool,
	certTimeout time.Duration,
) error {
	if order.Certificate == "" {
		return errors.New("в заказе нет URL сертификата")
	}
	if strings.TrimSpace(cp.PrivateKeyPEM) == "" {
		return fmt.Errorf("в чекпоинте нет private_key_pem — удалите %s и начните выпуск заново", obtainCheckpointPath(outDir))
	}

	certs, err := core.Certificates.GetAll(order.Certificate, bundle)
	if err != nil {
		return err
	}
	main, ok := certs[order.Certificate]
	if !ok || main == nil {
		return errors.New("пустой ответ Certificates.GetAll")
	}

	if err := writeCertBundle(outDir, main.Cert, []byte(cp.PrivateKeyPEM), main.Issuer); err != nil {
		return err
	}
	return removeObtainCheckpoint(outDir)
}

func pollOrderUntilCert(core *api.Core, orderURI string, certRes *certificate.Resource, bundle bool, certTimeout time.Duration) error {
	if certTimeout <= 0 {
		certTimeout = 30 * time.Second
	}
	return wait.For("certificate", certTimeout, certTimeout/60, func() (bool, error) {
		ord, err := core.Orders.Get(orderURI)
		if err != nil {
			return false, err
		}
		switch ord.Status {
		case acme.StatusValid:
			if ord.Certificate == "" {
				return false, nil
			}
			certs, err := core.Certificates.GetAll(ord.Certificate, bundle)
			if err != nil {
				return false, err
			}
			main, ok := certs[ord.Certificate]
			if !ok || main == nil {
				return false, errors.New("GetAll: нет основного сертификата")
			}
			certRes.Certificate = main.Cert
			certRes.IssuerCertificate = main.Issuer
			certRes.CertURL = ord.Certificate
			certRes.CertStableURL = ord.Certificate
			return true, nil
		case acme.StatusInvalid:
			return false, ord.Err()
		default:
			return false, nil
		}
	})
}

func finalizeOrderCSR(
	core *api.Core,
	certOpts certificate.CertifierOptions,
	domains []string,
	order acme.ExtendedOrder,
	cp *obtainCheckpoint,
	outDir string,
	bundle bool,
) error {
	priv, err := loadOrGeneratePrivateKey(cp, certOpts.KeyType)
	if err != nil {
		return err
	}
	if err := saveObtainCheckpoint(outDir, cp); err != nil {
		return fmt.Errorf("чекпоинт перед finalize: %w", err)
	}

	csr, err := createCSRForOrder(domains, order, priv, certOpts)
	if err != nil {
		return err
	}

	respOrder, err := core.Orders.UpdateForCSR(order.Finalize, csr)
	if err != nil {
		return fmt.Errorf("UpdateForCSR: %w", err)
	}

	certRes := &certificate.Resource{
		Domain:  domains[0],
		CertURL: respOrder.Certificate,
		PrivateKey: []byte(cp.PrivateKeyPEM),
	}

	if respOrder.Status == acme.StatusValid && respOrder.Certificate != "" {
		certs, err := core.Certificates.GetAll(respOrder.Certificate, bundle)
		if err != nil {
			return err
		}
		main, ok := certs[respOrder.Certificate]
		if !ok || main == nil {
			return errors.New("GetAll после finalize: пусто")
		}
		certRes.Certificate = main.Cert
		certRes.IssuerCertificate = main.Issuer
	} else {
		if err := pollOrderUntilCert(core, order.Location, certRes, bundle, certOpts.Timeout); err != nil {
			return err
		}
	}

	if err := writeCertBundle(outDir, certRes.Certificate, certRes.PrivateKey, certRes.IssuerCertificate); err != nil {
		return err
	}
	return removeObtainCheckpoint(outDir)
}

// runObtainWithCheckpoint выполняет выпуск с файлом .obtain-checkpoint.json в output_dir.
func runObtainWithCheckpoint(
	core *api.Core,
	prober *resolver.Prober,
	certOpts certificate.CertifierOptions,
	solver *fastDNSsolver,
	exp ExpandedCert,
) error {
	outDir := exp.OutputDir
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	sanitized, err := sanitizeObtainDomains(exp.Domains)
	if err != nil {
		return err
	}

	if old, err := loadObtainCheckpoint(outDir); err == nil && !domainsEqualObtain(old.Domains, sanitized) {
		slog.Debug("чекпоинт с другим списком доменов — удаляем", "path", obtainCheckpointPath(outDir))
		_ = removeObtainCheckpoint(outDir)
	}

	cp, errCP := loadObtainCheckpoint(outDir)
	reuse := errCP == nil && domainsEqualObtain(cp.Domains, sanitized) && cp.OrderURI != ""

	var order acme.ExtendedOrder

	if reuse {
		slog.Info("возобновление выпуска по чекпоинту", "label", exp.Label, "order_uri", cp.OrderURI, "txt_records", len(cp.TXTRecordIDs))
		order, err = core.Orders.Get(cp.OrderURI)
		if err != nil {
			slog.Warn("чекпоинт недействителен — новый заказ", "err", err)
			_ = removeObtainCheckpoint(outDir)
			reuse = false
		} else if order.Status == acme.StatusInvalid {
			slog.Warn("чекпоинт недействителен — заказ invalid", "status", order.Status)
			_ = removeObtainCheckpoint(outDir)
			reuse = false
		}
	}

	if reuse && order.Status == acme.StatusValid && order.Certificate != "" {
		return downloadAndWriteCert(core, order, cp, outDir, true, certOpts.Timeout)
	}

	if reuse {
		solver.restoreTXTRecordIDs(cp.TXTRecordIDs)
	}

	if !reuse {
		cp = &obtainCheckpoint{
			Version:      obtainCheckpointVersion,
			Domains:      append([]string(nil), sanitized...),
			TXTRecordIDs: map[string]string{},
		}
		order, err = core.Orders.NewWithOptions(sanitized, &api.OrderOptions{})
		if err != nil {
			return fmt.Errorf("NewOrder: %w", err)
		}
		cp.OrderURI = order.Location
		if err := saveObtainCheckpoint(outDir, cp); err != nil {
			return fmt.Errorf("чекпоинт после NewOrder: %w", err)
		}
		slog.Debug("новый заказ ACME", "order_uri", order.Location)
	}

	authz, err := fetchAuthorizationsSequential(core, order)
	if err != nil {
		return err
	}

	if !authzAllValid(authz) {
		attachCheckpointTXTHook(solver, outDir)
		slog.Info("запрос DNS-01 (prober)", "label", exp.Label, "authorizations", len(authz))
		if err := prober.Solve(authz); err != nil {
			return fmt.Errorf("Solve DNS-01: %w", err)
		}
	} else {
		slog.Info("все авторизации уже valid — пропуск Solve", "label", exp.Label)
	}

	// lego Orders.Get заполняет только тело заказа и не проставляет ExtendedOrder.Location
	// (Location приходит только из заголовка при NewOrder). При возобновлении по чекпоинту
	// order.Location пустой — повторный Get("") даёт order[get]: empty URL.
	orderURI := strings.TrimSpace(order.Location)
	if orderURI == "" {
		orderURI = strings.TrimSpace(cp.OrderURI)
	}
	if orderURI == "" {
		return errors.New("пустой URL заказа ACME после DNS-01 (internal)")
	}

	order, err = core.Orders.Get(orderURI)
	if err != nil {
		return fmt.Errorf("повторный GET заказа: %w", err)
	}
	order.Location = orderURI

	// Ждём ready (иногда сразу после Solve статус ещё pending)
	for i := 0; i < 90 && order.Status == acme.StatusPending; i++ {
		time.Sleep(1 * time.Second)
		order, err = core.Orders.Get(orderURI)
		if err != nil {
			return err
		}
		order.Location = orderURI
	}

	if order.Status == acme.StatusValid && order.Certificate != "" {
		return downloadAndWriteCert(core, order, cp, outDir, true, certOpts.Timeout)
	}

	if order.Status != acme.StatusReady && order.Status != acme.StatusProcessing {
		return fmt.Errorf("заказ в неожиданном статусе %q после DNS-01", order.Status)
	}

	if order.Status == acme.StatusProcessing {
		cpDisk, err := loadObtainCheckpoint(outDir)
		if err != nil {
			return fmt.Errorf("чекпоинт для processing: %w", err)
		}
		cp = cpDisk
		certRes := &certificate.Resource{Domain: sanitized[0]}
		if err := pollOrderUntilCert(core, order.Location, certRes, true, certOpts.Timeout); err != nil {
			return err
		}
		if err := writeCertBundle(outDir, certRes.Certificate, certRes.PrivateKey, certRes.IssuerCertificate); err != nil {
			return err
		}
		return removeObtainCheckpoint(outDir)
	}

	return finalizeOrderCSR(core, certOpts, sanitized, order, cp, outDir, true)
}
