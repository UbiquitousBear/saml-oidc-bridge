package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"

	"shamilnunhuck/saml-oidc-bridge/internal/cli"
	"shamilnunhuck/saml-oidc-bridge/internal/config"
	"shamilnunhuck/saml-oidc-bridge/internal/crypto"
	h "shamilnunhuck/saml-oidc-bridge/internal/http"
	"shamilnunhuck/saml-oidc-bridge/internal/oidc"
	"shamilnunhuck/saml-oidc-bridge/internal/saml"
)

type runtimeState struct {
	mu   sync.RWMutex
	cfg  *config.Config
	ks   *crypto.KeyStore
	idp  *saml.IdP
	oidc *oidc.Client
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "cert" {
		if err := cli.RunCert(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "example.config.yaml"
	}

	state := &runtimeState{}
	load := func() {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		if v := os.Getenv("OIDC_CLIENT_SECRET"); v != "" {
			cfg.OIDC.ClientSecret = v
		}
		if err := cfg.Validate(); err != nil {
			log.Fatalf("invalid config: %v", err)
		}

		ks, err := crypto.NewKeyStore(cfg.Crypto)
		if err != nil {
			log.Fatalf("keystore: %v", err)
		}
		idp := saml.NewIdP(cfg, ks)
		oc, err := oidc.NewClient(cfg)
		if err != nil {
			log.Fatalf("oidc: %v", err)
		}

		state.mu.Lock()
		state.cfg, state.ks, state.idp, state.oidc = cfg, ks, idp, oc
		state.mu.Unlock()
		log.Printf("loaded config; active signing key=%s", cfg.Crypto.ActiveKey)
	}
	load()

	mux := http.NewServeMux()
	h.Register(
		mux,
		func() *config.Config { state.mu.RLock(); defer state.mu.RUnlock(); return state.cfg },
		func() *saml.IdP { state.mu.RLock(); defer state.mu.RUnlock(); return state.idp },
		func() *oidc.Client { state.mu.RLock(); defer state.mu.RUnlock(); return state.oidc },
	)

	go func() {
		log.Printf("listening on %s", state.cfg.Server.Listen)
		log.Fatal(http.ListenAndServe(state.cfg.Server.Listen, mux))
	}()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP)
	go func() {
		for range sigc {
			load()
		}
	}()

	w, err := fsnotify.NewWatcher()
	if err == nil {
		defer w.Close()
		_ = w.Add(cfgPath)
		go func() {
			for {
				select {
				case e := <-w.Events:
					if e.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
						load()
					}
				case err := <-w.Errors:
					if err != nil {
						log.Printf("watch error: %v", err)
					}
				}
			}
		}()
	}

	select {}
}
