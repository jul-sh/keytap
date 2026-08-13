APP_NAME = Keytap
BUNDLE = $(APP_NAME).app
BIN = $(BUNDLE)/Contents/MacOS/keytap
LAUNCHER_SOURCE = macos/keytap-launcher.sh
BUNDLE_LAUNCHER = $(BUNDLE)/Contents/Resources/keytap-launcher
IDENTITY ?= -
PROVISIONING_PROFILE ?= $(wildcard Keytap.provisionprofile)
UNAME_S := $(shell uname -s)
MACOS_TEST_TARGET := $(if $(filter Darwin,$(UNAME_S)),test-macos,)

.PHONY: all build build-wasm build-web sign install verify test test-cargo test-macos test-web clean

all: sign

build:
	MACOSX_DEPLOYMENT_TARGET=15.0 cargo build --release -p keytap --locked
	@mkdir -p $(BUNDLE)/Contents/MacOS $(BUNDLE)/Contents/Resources
	@VERSION=$$(cargo metadata --no-deps --format-version 1 | \
		python3 -c 'import json, sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "keytap"))') && \
		sed "s/@VERSION@/$$VERSION/g" macos/Info.plist.in > $(BUNDLE)/Contents/Info.plist
	@cp target/release/keytap $(BIN)
	@install -m 755 $(LAUNCHER_SOURCE) $(BUNDLE_LAUNCHER)
	@echo "Built $(BUNDLE)"

build-wasm:
	@rm -rf web/pkg
	wasm-pack build web/wasm --target web --out-dir ../pkg --out-name keytap_web --release --locked

build-web:
	@rm -rf web/dist
	@$(MAKE) build-wasm
	@mkdir -p web/dist/pkg web/dist/.well-known
	@cp web/nearby.html web/nearby.js web/nearby-protocol.js \
		web/nearby.css web/nearby-sas-words.txt web/theme.css web/CNAME web/dist/
	@cp web/pkg/keytap_web.js web/pkg/keytap_web_bg.wasm web/dist/pkg/
	@cp .well-known/apple-app-site-association web/dist/.well-known/
	@echo "Built web/dist"

sign: build
	@rm -f $(BUNDLE)/Contents/embedded.provisionprofile
	@if [ -n "$(PROVISIONING_PROFILE)" ]; then \
		test -f "$(PROVISIONING_PROFILE)" || { echo "error: provisioning profile not found: $(PROVISIONING_PROFILE)" >&2; exit 1; }; \
		cp "$(PROVISIONING_PROFILE)" $(BUNDLE)/Contents/embedded.provisionprofile; \
		echo "Embedded $(PROVISIONING_PROFILE)"; \
	fi
	codesign --force --options runtime --timestamp \
		--sign "$(IDENTITY)" \
		--entitlements macos/keytap.entitlements $(BUNDLE)
	@echo "Signed $(BUNDLE)"

INSTALL_DIR = $(HOME)/.local/share/keytap
INSTALL_BUNDLE = $(INSTALL_DIR)/$(BUNDLE)
INSTALL_LAUNCHER = $(HOME)/.local/bin/keytap

install: sign
	@mkdir -p $(HOME)/.local/bin
	@rm -rf $(INSTALL_BUNDLE)
	@mkdir -p $(INSTALL_DIR)
	@cp -R $(BUNDLE) $(INSTALL_BUNDLE)
	@rm -f $(INSTALL_LAUNCHER)
	@install -m 755 $(INSTALL_BUNDLE)/Contents/Resources/keytap-launcher $(INSTALL_LAUNCHER)
	@KEYTAP_APP_BUNDLE="$(INSTALL_BUNDLE)" KEYTAP_LAUNCHER_REGISTER_ONLY=1 $(INSTALL_LAUNCHER)
	@echo "Installed: $(INSTALL_BUNDLE)"
	@echo "Registered with LaunchServices"
	@echo "Installed launcher: ~/.local/bin/keytap"

verify:
	codesign --verify --deep --strict --verbose=2 $(BUNDLE)
	codesign -dvv $(BUNDLE) 2>&1
	@echo ""
	codesign -d --entitlements - $(BUNDLE)

test: test-cargo $(MACOS_TEST_TARGET) test-web
	@echo "All tests passed."

test-cargo:
	cargo test -p keytap-core -p keytap -p keytap-web --locked

test-macos:
	swift test --package-path macos/swift-lib
	./macos/keytap-launcher.test.sh

test-web:
	npm --prefix web test

clean:
	cargo clean
	rm -rf $(BUNDLE) web/pkg web/dist
