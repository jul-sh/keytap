APP_NAME = Keytap
BUNDLE = $(APP_NAME).app
BIN = $(BUNDLE)/Contents/MacOS/keytap
IDENTITY ?= $(shell security find-identity -v -p codesigning 2>/dev/null | grep -q "Developer ID Application" && echo "Developer ID Application" || echo "-")
PROVISIONING_PROFILE ?=

.PHONY: all build build-wasm sign notarize setup-signing install verify package test test-core test-cli clean

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
	@cp macos/Info.plist $(BUNDLE)/Contents/Info.plist
	@cp macos/keytap.icns $(BUNDLE)/Contents/Resources/keytap.icns
	@cp target/release/keytap $(BIN)
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
INSTALL_BIN = $(INSTALL_BUNDLE)/Contents/MacOS/keytap

install: setup-signing all
	@mkdir -p $(HOME)/.local/bin
	@rm -rf $(INSTALL_BUNDLE)
	@mkdir -p $(INSTALL_DIR)
	@cp -R $(BUNDLE) $(INSTALL_BUNDLE)
	@ln -sf $(INSTALL_BIN) $(HOME)/.local/bin/keytap
	@echo "Installed: $(INSTALL_BUNDLE)"
	@echo "Symlinked: ~/.local/bin/keytap -> $(INSTALL_BIN)"

verify:
	codesign -dvv $(BUNDLE) 2>&1
	@echo ""
	codesign -d --entitlements :- $(BUNDLE)

build-wasm:
	wasm-pack build --target web web/wasm --out-dir ../pkg --out-name keytap_web

test: test-core test-cli
	@echo "All tests passed."

test-core:
	cargo test -p keytap-core

test-cli:
	cargo test -p keytap --no-default-features --test e2e_crypto

clean:
	cargo clean
	rm -rf $(BUNDLE)
