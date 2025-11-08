package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Validate() error {
	if c.Server.ExternalURL == "" || c.Server.Listen == "" {
		return fmt.Errorf("server.external_url and server.listen required")
	}
	if len(c.SPs) == 0 {
		return fmt.Errorf("at least one SP required")
	}
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" || c.OIDC.RedirectPath == "" {
		return fmt.Errorf("oidc issuer/client_id/redirect_path required")
	}
	if c.Crypto.ActiveKey == "" || len(c.Crypto.Keys) == 0 {
		return fmt.Errorf("crypto.active_key and at least one key required")
	}
	return nil
}
