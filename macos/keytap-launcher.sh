#!/bin/sh

set -u

keytap_bundle=${KEYTAP_APP_BUNDLE:-"$HOME/.local/share/keytap/Keytap.app"}
keytap_binary="$keytap_bundle/Contents/MacOS/keytap"
keytap_lsregister=${KEYTAP_LSREGISTER:-/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister}
keytap_sleep=${KEYTAP_SLEEP:-/bin/sleep}
keytap_cache_dir=${KEYTAP_CACHE_DIR:-"$HOME/Library/Caches/keytap"}
keytap_info_plist="$keytap_bundle/Contents/Info.plist"

if [ ! -x "$keytap_binary" ]; then
  echo "error: Keytap.app executable is missing or not executable: $keytap_binary" >&2
  exit 1
fi

if [ ! -f "$keytap_info_plist" ]; then
  echo "error: Keytap.app Info.plist is missing: $keytap_info_plist" >&2
  exit 1
fi

keytap_bundle_hash=$(
  {
    /usr/bin/shasum -a 256 "$keytap_binary"
    /usr/bin/shasum -a 256 "$keytap_info_plist"
    if [ -f "$keytap_bundle/Contents/embedded.provisionprofile" ]; then
      /usr/bin/shasum -a 256 "$keytap_bundle/Contents/embedded.provisionprofile"
    else
      printf '%s\n' no-provisioning-profile
    fi
  } | /usr/bin/shasum -a 256 | /usr/bin/cut -d ' ' -f 1
)
keytap_registration_id=$(
  printf '%s\n' "$keytap_bundle" \
    | /usr/bin/shasum -a 256 \
    | /usr/bin/cut -d ' ' -f 1
)
keytap_registration_marker="$keytap_cache_dir/launchservices-$keytap_registration_id"
keytap_registered_hash=$(/bin/cat "$keytap_registration_marker" 2>/dev/null || :)

if [ "$keytap_registered_hash" != "$keytap_bundle_hash" ]; then
  if "$keytap_lsregister" -f "$keytap_bundle" >/dev/null; then
    # LaunchServices returns before the associated-domain metadata is always
    # ready. Give each new bundle revision a bounded settling window. The
    # marker records a content hash, so same-version replacements re-register.
    "$keytap_sleep" 2
    keytap_registration_tmp="$keytap_registration_marker.$$"
    if ! /bin/mkdir -p "$keytap_cache_dir" \
      || ! printf '%s\n' "$keytap_bundle_hash" >"$keytap_registration_tmp" \
      || ! /bin/mv -f "$keytap_registration_tmp" "$keytap_registration_marker"
    then
      /bin/rm -f "$keytap_registration_tmp"
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
