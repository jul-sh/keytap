APP_NAME = PrfCli
BUNDLE = $(APP_NAME).app
BIN = $(BUNDLE)/Contents/MacOS/prf-cli
IDENTITY ?= $(shell security find-identity -v -p codesigning 2>/dev/null | grep -q "Developer ID Application" && echo "Developer ID Application" || echo "-")
PROVISIONING_PROFILE ?=

.PHONY: all build sign setup-signing install verify clean

all: build sign

setup-signing:
	@./distribution/setup-signing.sh

build:
	@mkdir -p $(BUNDLE)/Contents/MacOS
	@cp Info.plist $(BUNDLE)/Contents/Info.plist
	swiftc -O -target arm64-apple-macos15.0 \
		-framework AuthenticationServices -framework AppKit \
		Sources/PrfCli.swift -o $(BIN)
	@echo "Built $(BUNDLE)"

sign:
	@if [ -n "$(PROVISIONING_PROFILE)" ]; then \
		echo "Embedding provisioning profile..."; \
		cp "$(PROVISIONING_PROFILE)" "$(BUNDLE)/Contents/embedded.provisionprofile"; \
	elif [ -f PrfCli.provisionprofile ]; then \
		echo "Embedding provisioning profile..."; \
		cp PrfCli.provisionprofile "$(BUNDLE)/Contents/embedded.provisionprofile"; \
	fi
	codesign --force --options runtime --timestamp \
		--sign "$(IDENTITY)" \
		--entitlements prf-cli.entitlements $(BUNDLE)
	@echo "Signed $(BUNDLE)"

INSTALL_DIR = $(HOME)/.local/share/prf-cli
INSTALL_BUNDLE = $(INSTALL_DIR)/$(BUNDLE)
INSTALL_BIN = $(INSTALL_BUNDLE)/Contents/MacOS/prf-cli

install: setup-signing all
	@mkdir -p $(HOME)/.local/bin
	@rm -rf $(INSTALL_BUNDLE)
	@mkdir -p $(INSTALL_DIR)
	@cp -R $(BUNDLE) $(INSTALL_BUNDLE)
	@ln -sf $(INSTALL_BIN) $(HOME)/.local/bin/prf-cli
	@echo "Installed: $(INSTALL_BUNDLE)"
	@echo "Symlinked: ~/.local/bin/prf-cli -> $(INSTALL_BIN)"

verify:
	codesign -dvv $(BUNDLE) 2>&1
	@echo ""
	codesign -d --entitlements :- $(BUNDLE)

clean:
	rm -rf $(BUNDLE)
