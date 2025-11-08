package saml

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"shamilnunhuck/saml-oidc-bridge/internal/config"
)

const (
	subjectConfirmationMethodBearer        = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	nameIDFormatEntity                     = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	authnContextPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	defaultAssertionTTL                    = 5 * time.Minute
)

func (i *IdP) BuildResponse(sp config.SP, nameID string, attrs map[string][]string, inResponseTo string) (*saml.Response, error) {
	now := saml.TimeNow()
	ttl := time.Duration(i.sec.AssertionTTLSec) * time.Second
	if ttl <= 0 {
		ttl = defaultAssertionTTL
	}
	skew := time.Duration(i.sec.SkewSeconds) * time.Second

	assertionID, err := newSAMLID()
	if err != nil {
		return nil, fmt.Errorf("generate assertion id: %w", err)
	}
	responseID, err := newSAMLID()
	if err != nil {
		return nil, fmt.Errorf("generate response id: %w", err)
	}

	audience := sp.Audience
	if audience == "" {
		audience = sp.EntityID
	}

	nameIDFormat := sp.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = string(saml.UnspecifiedNameIDFormat)
	}

	assertion := &saml.Assertion{
		ID:           assertionID,
		IssueInstant: now,
		Version:      "2.0",
		Issuer: saml.Issuer{
			Format: nameIDFormatEntity,
			Value:  i.entityID,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format: nameIDFormat,
				Value:  nameID,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: subjectConfirmationMethodBearer,
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						InResponseTo: inResponseTo,
						NotOnOrAfter: now.Add(ttl),
						Recipient:    sp.ACSURL,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    now.Add(-skew),
			NotOnOrAfter: now.Add(ttl),
			AudienceRestrictions: []saml.AudienceRestriction{
				{
					Audience: saml.Audience{Value: audience},
				},
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnInstant: now,
				SessionIndex: responseID,
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{Value: authnContextPasswordProtectedTransport},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: toSAMLAttributes(attrs),
			},
		},
	}

	resp := &saml.Response{
		ID:           responseID,
		Version:      "2.0",
		IssueInstant: now,
		InResponseTo: inResponseTo,
		Destination:  sp.ACSURL,
		Issuer: &saml.Issuer{
			Format: nameIDFormatEntity,
			Value:  i.entityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
		Assertion: assertion,
	}

	if err := i.signResponse(resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (i *IdP) signingContext() (*dsig.SigningContext, error) {
	keyPair := i.keys.Active()
	if len(keyPair.Certificate) == 0 || keyPair.PrivateKey == nil {
		return nil, errors.New("active key missing certificate or private key")
	}

	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(keyPair))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	ctx.Hash = crypto.SHA256
	return ctx, nil
}

func (i *IdP) signResponse(resp *saml.Response) error {
	if resp.Assertion == nil {
		return errors.New("response missing assertion")
	}

	assertionCtx, err := i.signingContext()
	if err != nil {
		return err
	}

	assertionEl := resp.Assertion.Element()
	signedAssertionEl, err := assertionCtx.SignEnveloped(assertionEl)
	if err != nil {
		return fmt.Errorf("sign assertion: %w", err)
	}
	sigEl, err := lastChildElement(signedAssertionEl)
	if err != nil {
		return fmt.Errorf("sign assertion: %w", err)
	}
	resp.Assertion.Signature = sigEl

	responseCtx, err := i.signingContext()
	if err != nil {
		return err
	}
	responseEl := resp.Element()
	signedResponseEl, err := responseCtx.SignEnveloped(responseEl)
	if err != nil {
		return fmt.Errorf("sign response: %w", err)
	}
	sigEl, err = lastChildElement(signedResponseEl)
	if err != nil {
		return fmt.Errorf("sign response: %w", err)
	}
	resp.Signature = sigEl
	return nil
}

func MarshalSignedResponse(resp *saml.Response) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("nil response")
	}
	if resp.Signature == nil {
		return nil, errors.New("response not signed")
	}

	doc := etree.NewDocument()
	doc.SetRoot(resp.Element())
	return doc.WriteToBytes()
}

func lastChildElement(parent *etree.Element) (*etree.Element, error) {
	children := parent.ChildElements()
	if len(children) == 0 {
		return nil, errors.New("no child elements found")
	}
	return children[len(children)-1], nil
}

func newSAMLID() (string, error) {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "_" + hex.EncodeToString(b[:]), nil
}
