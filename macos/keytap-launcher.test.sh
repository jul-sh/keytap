#!/bin/sh

set -eu

case "$(/usr/bin/basename -- "$0")" in
  lsregister)
    printf 'lsregister:%s\n' "$*" >>"$KEYTAP_LAUNCHER_TEST_LOG"
    exit 0
    ;;
  sleep)
    printf 'sleep:%s\n' "$*" >>"$KEYTAP_LAUNCHER_TEST_LOG"
    exit 0
    ;;
  keytap)
    for argument in "$@"; do
      printf 'argument:%s\n' "$argument" >>"$KEYTAP_LAUNCHER_TEST_LOG"
    done
    exit 0
    ;;
esac

test_root=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/keytap-launcher.XXXXXX")
trap '/bin/rm -rf "$test_root"' EXIT HUP INT TERM

test_bundle="$test_root/Keytap Test.app"
test_binary="$test_bundle/Contents/MacOS/keytap"
test_lsregister="$test_root/lsregister"
test_sleep="$test_root/sleep"
test_log="$test_root/events"
test_cache="$test_root/cache"
test_script_dir=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && pwd)
test_script="$test_script_dir/keytap-launcher.test.sh"
test_launcher="$test_script_dir/keytap-launcher.sh"

/bin/mkdir -p "$test_bundle/Contents/MacOS"
/bin/ln -s "$test_script" "$test_binary"
/bin/ln -s "$test_script" "$test_lsregister"
/bin/ln -s "$test_script" "$test_sleep"
printf '%s\n' '<plist><dict><key>CFBundleVersion</key><string>9.0.0</string></dict></plist>' \
  >"$test_bundle/Contents/Info.plist"

KEYTAP_APP_BUNDLE="$test_bundle" \
  KEYTAP_CACHE_DIR="$test_cache" \
  KEYTAP_LAUNCHER_REGISTER_ONLY=1 \
  KEYTAP_LAUNCHER_TEST_LOG="$test_log" \
  KEYTAP_LSREGISTER="$test_lsregister" \
  KEYTAP_SLEEP="$test_sleep" \
  "$test_launcher"

KEYTAP_APP_BUNDLE="$test_bundle" \
  KEYTAP_CACHE_DIR="$test_cache" \
  KEYTAP_LAUNCHER_TEST_LOG="$test_log" \
  KEYTAP_LSREGISTER="$test_lsregister" \
  KEYTAP_SLEEP="$test_sleep" \
  "$test_launcher" 'argument with spaces' --flag

# Replacing bundle contents without changing CFBundleVersion must register the
# new revision rather than trusting the previous marker.
/bin/cp "$test_script" "$test_root/replacement-keytap"
printf '\n' >>"$test_root/replacement-keytap"
/bin/chmod 755 "$test_root/replacement-keytap"
/bin/rm "$test_binary"
/bin/mv "$test_root/replacement-keytap" "$test_binary"

KEYTAP_APP_BUNDLE="$test_bundle" \
  KEYTAP_CACHE_DIR="$test_cache" \
  KEYTAP_LAUNCHER_REGISTER_ONLY=1 \
  KEYTAP_LAUNCHER_TEST_LOG="$test_log" \
  KEYTAP_LSREGISTER="$test_lsregister" \
  KEYTAP_SLEEP="$test_sleep" \
  "$test_launcher"

expected_log="$test_root/expected"
printf 'lsregister:-f %s\n' "$test_bundle" >"$expected_log"
printf 'sleep:2\n' >>"$expected_log"
printf 'argument:argument with spaces\nargument:--flag\n' >>"$expected_log"
printf 'lsregister:-f %s\n' "$test_bundle" >>"$expected_log"
printf 'sleep:2\n' >>"$expected_log"

/usr/bin/diff -u "$expected_log" "$test_log"
test "$(/usr/bin/find "$test_cache" -type f -name 'launchservices-*' | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = 1

echo "keytap launcher tests passed"
