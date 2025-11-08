package config

import "time"

type Server struct {
	Listen      string `yaml:"listen"`
	ExternalURL string `yaml:"external_url"`
}

type KeyPair struct {
	ID       string    `yaml:"id"`
	CertPEM  string    `yaml:"cert_pem"`
	KeyPEM   string    `yaml:"key_pem"`
	NotAfter time.Time `yaml:"not_after"`
}
type Crypto struct {
	ActiveKey string    `yaml:"active_key"`
	Keys      []KeyPair `yaml:"keys"`
}

type OIDC struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"-"`
	RedirectPath string   `yaml:"redirect_path"`
	Scopes       []string `yaml:"scopes"`
}

type SP struct {
	Name             string            `yaml:"name"`
	EntityID         string            `yaml:"entity_id"`
	ACSURL           string            `yaml:"acs_url"`
	Audience         string            `yaml:"audience"`
	NameIDFormat     string            `yaml:"nameid_format"`
	AttributeMapping map[string]string `yaml:"attribute_mapping"`
	RoleMapping      map[string]string `yaml:"role_mapping"`
	AttributeRules   []AttributeRule   `yaml:"attribute_rules"`
}

type Security struct {
	SkewSeconds                  int  `yaml:"skew_seconds"`
	AssertionTTLSec              int  `yaml:"assertion_ttl_seconds"`
	RequireSignedAuthnRequest    bool `yaml:"require_signed_authn_request"`
	MetadataValidUntilDays       int  `yaml:"metadata_valid_until_days"`
	MetadataCacheDurationSeconds int  `yaml:"metadata_cache_duration_seconds"`
}

type Session struct {
	CookieName   string `yaml:"cookie_name"`
	CookieSecure bool   `yaml:"cookie_secure"`
	CookieDomain string `yaml:"cookie_domain"`
}

type Config struct {
	Server   Server   `yaml:"server"`
	Crypto   Crypto   `yaml:"crypto"`
	OIDC     OIDC     `yaml:"oidc_upstream"`
	SPs      []SP     `yaml:"sps"`
	Security Security `yaml:"security"`
	Session  Session  `yaml:"session"`
}

type AttributeRule struct {
	Name          string   `yaml:"name"`
	Value         string   `yaml:"value"`
	IfGroupsAny   []string `yaml:"if_groups_any"`
	EmitWhenFalse bool     `yaml:"emit_when_false"`
}
