package http

import (
	"compress/flate"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"

	"shamilnunhuck/saml-oidc-bridge/internal/config"
	"shamilnunhuck/saml-oidc-bridge/internal/oidc"
	idsaml "shamilnunhuck/saml-oidc-bridge/internal/saml"
)

type IdP interface {
	Metadata() *saml.EntityDescriptor
	BuildResponse(sp config.SP, nameID string, attrs map[string][]string) (*saml.Response, error)
}

func Register(
	mux *http.ServeMux,
	getCfg func() *config.Config,
	getIdP func() *idsaml.IdP,
	getOIDC func() *oidc.Client,
) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/saml/metadata", func(w http.ResponseWriter, r *http.Request) {
		meta := getIdP().Metadata()
		buf, err := xml.MarshalIndent(meta, "", "  ")
		if err != nil {
			http.Error(w, "marshal metadata: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(xml.Header))
		_, _ = w.Write(buf)
	})

	mux.HandleFunc("/saml/sso", func(w http.ResponseWriter, r *http.Request) {
		req, spEntityID, relay, err := parseAuthnRequest(r)
		log.Printf("AuthnRequest from SP=%s requestID=%s relay=%q", spEntityID, req.ID, relay)
		if err != nil {
			http.Error(w, "bad authn request: "+err.Error(), 400)
			return
		}
		setStateCookie(w, getCfg().Session, spEntityID, relay, req.ID)
		state := randomState()
		http.Redirect(w, r, getOIDC().AuthCodeURL(state, url.Values{}), http.StatusFound)
	})

	mux.HandleFunc(getCfg().OIDC.RedirectPath, func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", 400)
			return
		}

		claims, err := getOIDC().ExchangeAndVerify(ctx, code)
		if err != nil {
			http.Error(w, "oidc: "+err.Error(), 400)
			return
		}

		s, err := readStateCookie(r, getCfg().Session)
		if err != nil {
			http.Error(w, "state missing", 400)
			return
		}

		sp := lookupSP(getCfg(), s.SPEntityID)
		if sp == nil {
			http.Error(w, "unknown SP", 400)
			return
		}

		attrs := map[string][]string{}
		for samlAttr, oidcClaim := range sp.AttributeMapping {
			switch oidcClaim {
			case "email":
				attrs[samlAttr] = []string{claims.Email}
			case "name":
				attrs[samlAttr] = []string{claims.Name}
			case "role":
				attrs[samlAttr] = []string{mapRole(claims.Groups, sp)}
			}
		}

		nameID := claims.Email
		groups := claims.Groups

		// Apply generic conditional attribute rules
		userGroups := toSet(groups) // []string -> set
		for _, rule := range sp.AttributeRules {
			if hasAnyGroup(userGroups, rule.IfGroupsAny) {
				if rule.Value == "" { // safe default
					attrs[rule.Name] = []string{"true"}
				} else {
					attrs[rule.Name] = []string{rule.Value}
				}
			} else if rule.EmitWhenFalse {
				attrs[rule.Name] = []string{"false"}
			}
		}

		resp, err := getIdP().BuildResponse(*sp, nameID, attrs, s.RequestID)
		if err != nil {
			http.Error(w, "saml: "+err.Error(), 500)
			return
		}

		xmlBytes, err := idsaml.MarshalSignedResponse(resp)
		if err != nil {
			http.Error(w, "sign: "+err.Error(), 500)
			return
		}

		postToACS(w, sp.ACSURL, base64.StdEncoding.EncodeToString(xmlBytes), s.RelayState)
	})
}

/*** helpers ***/

type state struct {
	SPEntityID string
	RelayState string
	RequestID  string
	Expiry     time.Time
}

func setStateCookie(w http.ResponseWriter, s config.Session, spEntityID, relay, reqID string) {
	v := url.Values{}
	v.Set("sp", spEntityID)
	v.Set("rs", relay)
	v.Set("rid", reqID)
	c := &http.Cookie{
		Name:     s.CookieName,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(v.Encode())),
		Path:     "/",
		Domain:   s.CookieDomain,
		HttpOnly: true,
		Secure:   s.CookieSecure,
		MaxAge:   600,
	}
	http.SetCookie(w, c)
}

func readStateCookie(r *http.Request, s config.Session) (*state, error) {
	c, err := r.Cookie(s.CookieName)
	if err != nil {
		return nil, err
	}
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, err
	}
	v, err := url.ParseQuery(string(b))
	if err != nil {
		return nil, err
	}
	return &state{
		SPEntityID: v.Get("sp"),
		RelayState: v.Get("rs"),
		RequestID:  v.Get("rid"),
		Expiry:     time.Now().Add(10 * time.Minute),
	}, nil
}

func lookupSP(cfg *config.Config, entityID string) *config.SP {
	for i := range cfg.SPs {
		if cfg.SPs[i].EntityID == entityID {
			return &cfg.SPs[i]
		}
	}
	return nil
}

func mapRole(groups []string, sp *config.SP) string {
	for _, g := range groups {
		if v, ok := sp.RoleMapping[g]; ok {
			return v
		}
	}
	if v, ok := sp.RoleMapping["*"]; ok {
		return v
	}
	return "user"
}

func postToACS(w http.ResponseWriter, acsURL string, samlResponseB64 string, relay string) {
	const tpl = `<!doctype html>
<html><body onload="document.forms[0].submit()">
<form method="post" action="{{.ACS}}">
  <input type="hidden" name="SAMLResponse" value="{{.Resp}}">
  {{if .Relay}}<input type="hidden" name="RelayState" value="{{.Relay}}">{{end}}
  <noscript><button type="submit">Continue</button></noscript>
</form></body></html>`
	t := template.Must(template.New("post").Parse(tpl))
	_ = t.Execute(w, map[string]string{"ACS": acsURL, "Resp": samlResponseB64, "Relay": relay})
}

func randomState() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func parseAuthnRequest(r *http.Request) (*saml.AuthnRequest, string, string, error) {
	relay := r.FormValue("RelayState")
	if sr := r.URL.Query().Get("SAMLRequest"); sr != "" {
		xmlBytes, err := base64.StdEncoding.DecodeString(sr)
		if err != nil {
			return nil, "", "", fmt.Errorf("b64: %w", err)
		}
		reader := flate.NewReader(strings.NewReader(string(xmlBytes)))
		defer reader.Close()
		var sb strings.Builder
		if _, err := io.Copy(&sb, reader); err != nil {
			return nil, "", "", fmt.Errorf("inflate: %w", err)
		}
		var req saml.AuthnRequest
		if err := xml.Unmarshal([]byte(sb.String()), &req); err != nil {
			return nil, "", "", fmt.Errorf("xml: %w", err)
		}
		sp := ""
		if req.Issuer != nil {
			sp = req.Issuer.Value
		}
		return &req, sp, relay, nil
	}
	if sr := r.FormValue("SAMLRequest"); sr != "" {
		xmlBytes, err := base64.StdEncoding.DecodeString(sr)
		if err != nil {
			return nil, "", "", fmt.Errorf("b64: %w", err)
		}
		var req saml.AuthnRequest
		if err := xml.Unmarshal(xmlBytes, &req); err != nil {
			return nil, "", "", fmt.Errorf("xml: %w", err)
		}
		sp := ""
		if req.Issuer != nil {
			sp = req.Issuer.Value
		}
		return &req, sp, relay, nil
	}
	return nil, "", "", fmt.Errorf("missing SAMLRequest")
}
