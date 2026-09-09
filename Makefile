APP_NAME = Keytap
BUNDLE = $(APP_NAME).app
BIN = $(BUNDLE)/Contents/MacOS/keytap
LAUNCHER_SOURCE = distribution/keytap-launcher.sh
BUNDLE_LAUNCHER = $(BUNDLE)/Contents/Resources/keytap-launcher
IDENTITY ?= $(shell security find-identity -v -p codesigning 2>/dev/null | grep -q "Developer ID Application" && echo "Developer ID Application" || echo "-")
PROVISIONING_PROFILE ?=
UNAME_S := $(shell uname -s)
MACOS_TEST_TARGET := $(if $(filter Darwin,$(UNAME_S)),test-macos,)

.PHONY: all build build-wasm sign notarize setup-signing install verify package test test-core test-spec test-cli test-macos test-wasm test-web clean

all: build sign notarize

package: setup-signing build sign verify notarize
	xattr -cr $(BUNDLE)
	@SHA=$$(git rev-parse --short=7 HEAD) && \
		ZIP_NAME="keytap-$${SHA}-arm64.zip" && \
		ditto -c -k --keepParent $(BUNDLE) "$$ZIP_NAME" && \
		echo "Packaged $$ZIP_NAME"

setup-signing:
	@./distribution/setup-signing.sh

build:
	cargo build --release -p keytap
	@mkdir -p $(BUNDLE)/Contents/MacOS $(BUNDLE)/Contents/Resources
	@VERSION=$$(cargo metadata --no-deps --format-version 1 | \
		python3 -c 'import json, sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "keytap"))') && \
		sed "s/@VERSION@/$$VERSION/g" macos/Info.plist.in > $(BUNDLE)/Contents/Info.plist
	@xcrun actool macos/keytap.icon --compile $(BUNDLE)/Contents/Resources \
		--platform macosx --minimum-deployment-target 15.0 \
		--app-icon keytap --include-all-app-icons \
		--output-partial-info-plist /dev/null > /dev/null
	@cp target/release/keytap $(BIN)
	@install -m 755 $(LAUNCHER_SOURCE) $(BUNDLE_LAUNCHER)
	@echo "Built $(BUNDLE)"

sign:
	@if [ -n "$(PROVISIONING_PROFILE)" ]; then \
		echo "Embedding provisioning profile..."; \
		cp "$(PROVISIONING_PROFILE)" "$(BUNDLE)/Contents/embedded.provisionprofile"; \
	elif [ -f Keytap.provisionprofile ]; then \
		echo "Embedding provisioning profile..."; \
		cp Keytap.provisionprofile "$(BUNDLE)/Contents/embedded.provisionprofile"; \
	fi
	codesign --force --options runtime --timestamp \
		--sign "$(IDENTITY)" \
		--entitlements macos/keytap.entitlements $(BUNDLE)
	@echo "Signed $(BUNDLE)"

notarize:
	@./distribution/notarize.sh $(BUNDLE)

INSTALL_DIR = $(HOME)/.local/share/keytap
INSTALL_BUNDLE = $(INSTALL_DIR)/$(BUNDLE)
INSTALL_LAUNCHER = $(HOME)/.local/bin/keytap

install: setup-signing all
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
	codesign -dvv $(BUNDLE) 2>&1
	@echo ""
	codesign -d --entitlements :- $(BUNDLE)

build-wasm:
	wasm-pack build --target web web/wasm --out-dir ../pkg --out-name keytap_web

test: test-core test-spec test-cli $(MACOS_TEST_TARGET) test-wasm test-web
	@echo "All tests passed."

test-core:
	cargo test -p keytap-core

test-spec:
	cargo test -p keytap-cli-spec

test-cli:
	cargo test -p keytap

test-macos:
	swift test --package-path macos/swift-lib
	./distribution/keytap-launcher.test.sh

test-wasm:
	cargo test -p keytap-web
	wasm-pack test --node web/wasm

test-web:
	npm --prefix web test

clean:
	cargo clean
	rm -rf $(BUNDLE)
