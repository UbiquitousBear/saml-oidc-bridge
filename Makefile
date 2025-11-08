APP?=saml-oidc-broker
PKG?=shamilnunhuck/saml-oidc-bridge
CONFIG?=example.config.yaml
KEY_ID?=k-$(shell date +%Y-%m)

build:
	GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(APP) ./cmd/broker

run:
	CONFIG_PATH=$(CONFIG) bin/$(APP)

rotate-key:
	bin/$(APP) cert -config $(CONFIG) -id $(KEY_ID) -algo rsa3072 -days 825 -cn id.example.com -org "YourOrg" -k8s-secret-out build/$(KEY_ID).secret.yaml
	@echo "Wrote build/$(KEY_ID).secret.yaml"

docker:
	docker build --platform linux/amd64 -t shamilnunhuck/$(APP):dev .

.PHONY: build run rotate-key docker
