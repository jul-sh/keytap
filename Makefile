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
		-framework AuthenticationServices -framework AppKit \
		Sources/Tapkey.swift -o $(BIN)
	@echo "Built $(BUNDLE)"

sign:
	codesign --force --options runtime --timestamp \
		--sign "$(IDENTITY)" \
		--entitlements tapkey.entitlements $(BUNDLE)
	@echo "Signed $(BUNDLE)"

install: all
	@cp -r $(BUNDLE) /Applications/
	@mkdir -p $(HOME)/.local/bin
	@ln -sf /Applications/$(BUNDLE)/Contents/MacOS/tapkey $(HOME)/.local/bin/tapkey
	@echo "Installed: /Applications/$(BUNDLE) + ~/.local/bin/tapkey"

verify:
	codesign -dvv $(BUNDLE) 2>&1
	@echo ""
	codesign -d --entitlements :- $(BUNDLE)

clean:
	rm -rf $(BUNDLE)
