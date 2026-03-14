APP_NAME = Tapkey
BUNDLE = $(APP_NAME).app
BIN = $(BUNDLE)/Contents/MacOS/tapkey
IDENTITY ?= Developer ID Application

.PHONY: all build sign install verify test clean

all: build sign

build:
	cargo build --release --manifest-path mac/Cargo.toml
	@mkdir -p $(BUNDLE)/Contents/MacOS
	@cp mac/Info.plist $(BUNDLE)/Contents/Info.plist
	@cp target/release/tapkey $(BIN)
	@echo "Built $(BUNDLE)"

sign:
	codesign --force --options runtime --timestamp \
		--sign "$(IDENTITY)" \
		--entitlements mac/tapkey.entitlements $(BUNDLE)
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

test:
	cargo test --workspace

clean:
	cargo clean
	rm -rf $(BUNDLE)
