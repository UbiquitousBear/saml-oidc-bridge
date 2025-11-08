package oidc

import (
	"context"
	"fmt"
	"net/url"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"shamilnunhuck/saml-oidc-bridge/internal/config"
)

type Client struct {
	Verifier *gooidc.IDTokenVerifier
	OAuth2   *oauth2.Config
}

func NewClient(cfg *config.Config) (*Client, error) {
	ctx := context.Background()
	provider, err := gooidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(&gooidc.Config{ClientID: cfg.OIDC.ClientID})
	redirect := cfg.Server.ExternalURL + cfg.OIDC.RedirectPath

	scopes := []string{"openid"}
	scopes = append(scopes, cfg.OIDC.Scopes...)

	oauth2cfg := &oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  redirect,
	}
	return &Client{Verifier: verifier, OAuth2: oauth2cfg}, nil
}

type Claims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Name    string   `json:"name"`
	Groups  []string `json:"groups"`
}

func (c *Client) AuthCodeURL(state string, extra url.Values) string {
	return c.OAuth2.AuthCodeURL(state)
}

func (c *Client) ExchangeAndVerify(ctx context.Context, code string) (*Claims, error) {
	token, err := c.OAuth2.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}
	idt, err := c.Verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, err
	}
	var cl Claims
	if err := idt.Claims(&cl); err != nil {
		return nil, err
	}
	return &cl, nil
}
