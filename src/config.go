package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config описывает TOML-конфиг (по умолчанию /etc/certbot-dns/config.toml).
type Config struct {
	ACME         ACMEConfig         `toml:"acme"`
	FastDNS      FastDNSConfig      `toml:"fastdns"`
	DNSChallenge DNSChallengeConfig `toml:"dns_challenge"`
	Certificates []CertConfig       `toml:"certificates"`
	Runtime      RuntimeConfig      `toml:"runtime"`
}

type ACMEConfig struct {
	Email     string `toml:"email"`
	Directory string `toml:"directory"` // production | staging
	StateDir  string `toml:"state_dir"`
	UserAgent string `toml:"user_agent"`
}

type FastDNSConfig struct {
	APIToken string `toml:"api_token"`
	APIURL   string `toml:"api_url"`
}

type DNSChallengeConfig struct {
	PropagationTimeout  string   `toml:"propagation_timeout"`
	PropagationInterval string   `toml:"propagation_interval"`
	// RecursiveResolvers — хост:порт резолверов для pre-check TXT (lego). Если не задано, в buildDNSOpts
	// подставляются публичные 8.8.8.8 и 1.1.1.1, чтобы не использовать только 127.0.0.53 (systemd-resolved),
	// который часто кэширует и не отражает то, что видит Let's Encrypt.
	RecursiveResolvers []string `toml:"recursive_resolvers"`
}

// CertConfig — один блок [[certificates]]: список domains разворачивается в несколько сертификатов
// (зона FastDNS и подкаталоги output_dir выводятся автоматически, см. ../config.example.toml).
type CertConfig struct {
	ID              string   `toml:"id"`
	Domains         []string `toml:"domains"`
	OutputDir       string   `toml:"output_dir"`
	KeyType         string   `toml:"key_type"`
	RenewBeforeDays int      `toml:"renew_before_days"`
}

type RuntimeConfig struct {
	Mode       string `toml:"mode"` // once | daemon
	PollWhenOK string `toml:"poll_when_ok"`
	Loglevel   string `toml:"loglevel"` // debug|verbose|info|warning|error|fatal
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := toml.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	c.applyDefaults()
	expandEnvInConfig(&c)
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.ACME.Directory == "" {
		c.ACME.Directory = "production"
	}
	if c.ACME.StateDir == "" {
		c.ACME.StateDir = ".acme-state"
	}
	if c.ACME.UserAgent == "" {
		c.ACME.UserAgent = "certbot-dns/1"
	}
	if c.DNSChallenge.PropagationTimeout == "" {
		c.DNSChallenge.PropagationTimeout = "24h"
	}
	if c.DNSChallenge.PropagationInterval == "" {
		c.DNSChallenge.PropagationInterval = "10m"
	}
	if c.Runtime.Mode == "" {
		c.Runtime.Mode = "once"
	}
	if c.Runtime.PollWhenOK == "" {
		c.Runtime.PollWhenOK = "24h"
	}
	if c.Runtime.Loglevel == "" {
		c.Runtime.Loglevel = "info"
	}
	for i := range c.Certificates {
		e := &c.Certificates[i]
		if e.RenewBeforeDays <= 0 {
			e.RenewBeforeDays = 25
		}
		if e.KeyType == "" {
			e.KeyType = "ec256"
		}
	}
}

func expandEnvInConfig(c *Config) {
	c.ACME.Email = os.ExpandEnv(c.ACME.Email)
	c.ACME.StateDir = os.ExpandEnv(c.ACME.StateDir)
	c.ACME.UserAgent = os.ExpandEnv(c.ACME.UserAgent)
	c.FastDNS.APIToken = os.ExpandEnv(c.FastDNS.APIToken)
	c.FastDNS.APIURL = os.ExpandEnv(c.FastDNS.APIURL)
	c.Runtime.Loglevel = os.ExpandEnv(c.Runtime.Loglevel)
	for i := range c.DNSChallenge.RecursiveResolvers {
		c.DNSChallenge.RecursiveResolvers[i] = os.ExpandEnv(c.DNSChallenge.RecursiveResolvers[i])
	}
	for i := range c.Certificates {
		e := &c.Certificates[i]
		e.ID = os.ExpandEnv(e.ID)
		e.OutputDir = os.ExpandEnv(e.OutputDir)
		for j := range e.Domains {
			e.Domains[j] = os.ExpandEnv(e.Domains[j])
		}
	}
}

func (c *Config) validate() error {
	if strings.TrimSpace(c.ACME.Email) == "" {
		return fmt.Errorf("acme.email обязателен")
	}
	dir := strings.ToLower(strings.TrimSpace(c.ACME.Directory))
	switch dir {
	case "production", "staging":
	default:
		return fmt.Errorf("acme.directory должен быть production или staging, сейчас %q", c.ACME.Directory)
	}
	if strings.TrimSpace(c.FastDNS.APIToken) == "" {
		return fmt.Errorf("fastdns.api_token пуст (можно ${FASTDNS_API_TOKEN})")
	}
	if _, err := time.ParseDuration(c.DNSChallenge.PropagationTimeout); err != nil {
		return fmt.Errorf("dns_challenge.propagation_timeout: %w", err)
	}
	if _, err := time.ParseDuration(c.DNSChallenge.PropagationInterval); err != nil {
		return fmt.Errorf("dns_challenge.propagation_interval: %w", err)
	}
	mode := strings.ToLower(strings.TrimSpace(c.Runtime.Mode))
	switch mode {
	case "once", "daemon":
	default:
		return fmt.Errorf("runtime.mode должен быть once или daemon, сейчас %q", c.Runtime.Mode)
	}
	if _, err := time.ParseDuration(c.Runtime.PollWhenOK); err != nil {
		return fmt.Errorf("runtime.poll_when_ok: %w", err)
	}
	if _, err := parseLoggingSetup(c.Runtime.Loglevel); err != nil {
		return err
	}
	if len(c.Certificates) == 0 {
		return fmt.Errorf("нужен хотя бы один блок [[certificates]]")
	}
	for i := range c.Certificates {
		e := &c.Certificates[i]
		if len(e.Domains) == 0 {
			return fmt.Errorf("certificates[%d].domains не может быть пустым", i)
		}
		if strings.TrimSpace(e.OutputDir) == "" {
			return fmt.Errorf("certificates[%d].output_dir обязателен", i)
		}
		if _, err := parseKeyType(e.KeyType); err != nil {
			return fmt.Errorf("certificates[%d].key_type: %w", i, err)
		}
		if _, err := expandCertEntry(*e, i); err != nil {
			return fmt.Errorf("certificates[%d] domains: %w", i, err)
		}
	}
	return nil
}

func (c *Config) propagationDurations() (timeout, interval time.Duration, err error) {
	timeout, err = time.ParseDuration(c.DNSChallenge.PropagationTimeout)
	if err != nil {
		return 0, 0, err
	}
	interval, err = time.ParseDuration(c.DNSChallenge.PropagationInterval)
	if err != nil {
		return 0, 0, err
	}
	return timeout, interval, nil
}

func (c *Config) pollWhenOKDuration() (time.Duration, error) {
	return time.ParseDuration(c.Runtime.PollWhenOK)
}

func (c *Config) runtimeMode() string {
	return strings.ToLower(strings.TrimSpace(c.Runtime.Mode))
}

func certLabel(c CertConfig, idx int) string {
	if strings.TrimSpace(c.ID) != "" {
		return c.ID
	}
	return fmt.Sprintf("#%d", idx)
}
