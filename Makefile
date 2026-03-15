APP_NAME = Tapkey
BUNDLE = $(APP_NAME).app
BIN = $(BUNDLE)/Contents/MacOS/tapkey
IDENTITY ?= $(shell security find-identity -v -p codesigning 2>/dev/null | grep -q "Developer ID Application" && echo "Developer ID Application" || echo "-")
PROVISIONING_PROFILE ?=

.PHONY: all build sign setup-signing install verify test clean

all: build sign

setup-signing:
	@./distribution/setup-signing.sh

build:
	cargo build --release -p tapkey
	@mkdir -p $(BUNDLE)/Contents/MacOS
	@cp mac/Info.plist $(BUNDLE)/Contents/Info.plist
	@cp target/release/tapkey $(BIN)
	@echo "Built $(BUNDLE)"

sign:
	@if [ -n "$(PROVISIONING_PROFILE)" ]; then \
		echo "Embedding provisioning profile..."; \
		cp "$(PROVISIONING_PROFILE)" "$(BUNDLE)/Contents/embedded.provisionprofile"; \
	elif [ -f Tapkey.provisionprofile ]; then \
		echo "Embedding provisioning profile..."; \
		cp Tapkey.provisionprofile "$(BUNDLE)/Contents/embedded.provisionprofile"; \
	fi
	codesign --force --options runtime --timestamp \
		--sign "$(IDENTITY)" \
		--entitlements mac/tapkey.entitlements $(BUNDLE)
	@echo "Signed $(BUNDLE)"

INSTALL_DIR = $(HOME)/.local/share/tapkey
INSTALL_BUNDLE = $(INSTALL_DIR)/$(BUNDLE)
INSTALL_BIN = $(INSTALL_BUNDLE)/Contents/MacOS/tapkey

install: setup-signing all
	@mkdir -p $(HOME)/.local/bin
	@rm -rf $(INSTALL_BUNDLE)
	@mkdir -p $(INSTALL_DIR)
	@cp -R $(BUNDLE) $(INSTALL_BUNDLE)
	@ln -sf $(INSTALL_BIN) $(HOME)/.local/bin/tapkey
	@echo "Installed: $(INSTALL_BUNDLE)"
	@echo "Symlinked: ~/.local/bin/tapkey -> $(INSTALL_BIN)"

verify:
	codesign -dvv $(BUNDLE) 2>&1
	@echo ""
	codesign -d --entitlements :- $(BUNDLE)

test:
	cargo test -p tapkey-core
	@echo "All tests passed."

clean:
	cargo clean
	rm -rf $(BUNDLE)
