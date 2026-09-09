#!/bin/sh

set -u

keytap_bundle=${KEYTAP_APP_BUNDLE:-"$HOME/.local/share/keytap/Keytap.app"}
keytap_binary="$keytap_bundle/Contents/MacOS/keytap"
keytap_lsregister=${KEYTAP_LSREGISTER:-/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister}
keytap_sleep=${KEYTAP_SLEEP:-/bin/sleep}
keytap_cache_dir=${KEYTAP_CACHE_DIR:-"$HOME/Library/Caches/keytap"}

if [ ! -x "$keytap_binary" ]; then
  echo "error: Keytap.app executable is missing or not executable: $keytap_binary" >&2
  exit 1
fi

keytap_bundle_version=$(
  /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$keytap_bundle/Contents/Info.plist" \
    2>/dev/null || printf '%s' unknown
)
keytap_registration_id=$(
  printf '%s\n%s\n' "$keytap_bundle" "$keytap_bundle_version" \
    | /usr/bin/shasum -a 256 \
    | /usr/bin/cut -d ' ' -f 1
)
keytap_registration_marker="$keytap_cache_dir/launchservices-$keytap_registration_id"

if [ ! -e "$keytap_registration_marker" ]; then
  if "$keytap_lsregister" -f "$keytap_bundle" >/dev/null; then
    # LaunchServices returns before the associated-domain metadata is always
    # ready. Give the first invocation of each installed bundle a bounded
    # settling window. The path-and-version marker avoids a global forced
    # registration on later invocations while detecting bundle replacements.
    "$keytap_sleep" 2
    if ! /bin/mkdir -p "$keytap_cache_dir" \
      || ! /usr/bin/touch "$keytap_registration_marker"
    then
      echo "warning: could not record Keytap.app registration; a later run may wait again" >&2
    fi
  else
    echo "warning: failed to register Keytap.app with LaunchServices; native passkeys may be unavailable" >&2
    if [ "${KEYTAP_LAUNCHER_REGISTER_ONLY:-0}" = 1 ]; then
      exit 1
    fi
  fi
fi

if [ "${KEYTAP_LAUNCHER_REGISTER_ONLY:-0}" = 1 ]; then
  exit 0
fi

exec "$keytap_binary" "$@"
