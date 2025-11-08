package saml

import "github.com/crewjam/saml"

const attrNameFormatURI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

func toSAMLAttributes(attrs map[string][]string) []saml.Attribute {
	out := make([]saml.Attribute, 0, len(attrs))
	for name, vals := range attrs {
		vs := make([]saml.AttributeValue, 0, len(vals))
		for _, s := range vals {
			vs = append(vs, saml.AttributeValue{
				// explicitly mark string type so we never emit xsi:type=""
				Type:  "xs:string",
				Value: s,
			})
		}
		out = append(out, saml.Attribute{
			FriendlyName: name,
			Name:         name,
			NameFormat:   attrNameFormatURI,
			Values:       vs,
		})
	}
	return out
}
