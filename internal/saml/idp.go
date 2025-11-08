package saml

import (
	"encoding/base64"
	"time"

	"shamilnunhuck/saml-oidc-bridge/internal/config"
	"shamilnunhuck/saml-oidc-bridge/internal/crypto"

	"github.com/crewjam/saml"
)

type IdP struct {
	keys     *crypto.KeyStore
	sec      config.Security
	entityID string
	ssoURL   string
}

func NewIdP(cfg *config.Config, ks *crypto.KeyStore) *IdP {
	return &IdP{
		keys:     ks,
		sec:      cfg.Security,
		entityID: cfg.Server.ExternalURL,
		ssoURL:   cfg.Server.ExternalURL + "/saml/sso",
	}
}

func (i *IdP) Metadata() *saml.EntityDescriptor {
	// we need to publish all certs, to allow safe rotation
	keyDescriptors := []saml.KeyDescriptor{}

	for _, der := range i.keys.AllCertsDER() {
		keyDescriptors = append(keyDescriptors, saml.KeyDescriptor{
			Use: "signing",
			KeyInfo: saml.KeyInfo{
				X509Data: saml.X509Data{
					X509Certificates: []saml.X509Certificate{{
						Data: base64.StdEncoding.EncodeToString(der),
					}},
				},
			},
		})
	}

	entityDescriptor := &saml.EntityDescriptor{
		EntityID: i.entityID,
		// crewjam expects time.Time for ValidUntil and time.Duration for CacheDuration
		ValidUntil:    time.Now().UTC().Add(time.Duration(i.sec.MetadataValidUntilDays) * 24 * time.Hour),
		CacheDuration: time.Duration(i.sec.MetadataCacheDurationSeconds) * time.Second,
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             keyDescriptors,
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPPostBinding,
						Location: i.ssoURL,
					},
				},
			},
		},
	}

	return entityDescriptor
}
