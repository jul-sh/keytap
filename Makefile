APP_NAME = Tapkey
BUNDLE = $(APP_NAME).app
BIN = $(BUNDLE)/Contents/MacOS/tapkey
IDENTITY ?= Developer ID Application

.PHONY: all build sign install verify clean

all: build sign

build:
	@mkdir -p $(BUNDLE)/Contents/MacOS
	@cp Info.plist $(BUNDLE)/Contents/Info.plist
	swiftc -O -target arm64-apple-macos15.0 \
		-framework AuthenticationServices -framework AppKit -framework WebKit \
		Sources/Tapkey.swift -o $(BIN)
	@echo "Built $(BUNDLE)"

sign:
	codesign --force --options runtime --timestamp \
		--sign "$(IDENTITY)" \
		--entitlements tapkey.entitlements $(BUNDLE)
	@echo "Signed $(BUNDLE)"

install: all
	@mkdir -p $(HOME)/.local/bin
	@ln -sf $(abspath $(BIN)) $(HOME)/.local/bin/tapkey
	@echo "Installed: ~/.local/bin/tapkey -> $(BIN)"

verify:
	codesign -dvv $(BUNDLE) 2>&1
	@echo ""
	codesign -d --entitlements :- $(BUNDLE)

clean:
	rm -rf $(BUNDLE)
