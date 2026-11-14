#!/bin/sh
# wp-fingerprint.sh — passive WordPress fingerprint for an authorized target.
# Usage: wp-fingerprint.sh https://target.example
# Prints evidence lines only; it does not exploit and does not mutate the target.
set -u

BASE="${1:-}"
if [ -z "$BASE" ]; then
  echo "usage: $0 <base-url>" >&2
  exit 2
fi
BASE="${BASE%/}"
TMP="${TMPDIR:-/tmp}/wp-fp.$$"
trap 'rm -f "$TMP" "$TMP".*' EXIT INT TERM

# NOTE: never assign the fetched body to HOME — HOME is exported, so a page body
# in it makes every later child process fail with E2BIG
# ("Argument list too long").
say() { printf '%-22s %s\n' "$1" "$2"; }
get() { curl -sS -m 15 -A "Mozilla/5.0 (compatible; ARTEX-recon)" "$1" 2>/dev/null; }

# --- confirmation signals (two independent ones = strong) ---
HITS=0
LOGIN=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' "$BASE/wp-login.php" 2>/dev/null)
say "wp-login.php" "$LOGIN"
case "$LOGIN" in 200|302) HITS=$((HITS+1));; esac

REST=$(get "$BASE/wp-json/")
if printf '%s' "$REST" | grep -q '"namespaces"'; then
  say "wp-json" "JSON with namespaces (confirmed)"
  HITS=$((HITS+1))
else
  say "wp-json" "no namespaces in body"
fi

# ?rest_route= reaches the SAME REST API, but non-WordPress apps also answer 200
# there: require JSON with WordPress route keys, not just a 200.
ROUTE=$(get "$BASE/?rest_route=/")
if printf '%s' "$ROUTE" | grep -qE '"(namespaces|routes)"'; then
  say "?rest_route=/" "WordPress REST payload (confirmed)"
  HITS=$((HITS+1))
else
  say "?rest_route=/" "no WordPress REST payload"
fi

PAGE=$(get "$BASE/")
GEN=$(printf '%s' "$PAGE" | grep -oiE '<meta name="generator" content="[^"]*"' | head -1)
[ -n "$GEN" ] && say "generator meta" "$GEN"
if printf '%s' "$PAGE" | grep -qiE 'wp-(includes|content)/'; then
  say "wp asset paths" "present"
  HITS=$((HITS+1))
fi
say "confirmation count" "$HITS (>=2 is strong)"

# --- core version (passive) ---
printf '%s' "$PAGE" | grep -oE 'wp-includes/[^"?]+\.(js|css)' | sort -u | head -5 \
  | sed 's/^/  core asset: /'

README=$(get "$BASE/readme.html")
V=$(printf '%s' "$README" | grep -oiE 'Version [0-9]+\.[0-9.]+' | head -1)
[ -n "$V" ] && say "readme.html" "$V"

FEED=$(get "$BASE/feed/")
FG=$(printf '%s' "$FEED" | grep -oiE '<generator>[^<]+' | head -1)
[ -n "$FG" ] && say "feed generator" "$FG"

# --- plugins / themes referenced by the rendered page ---
printf '%s' "$PAGE" | grep -oE '/wp-content/plugins/[a-z0-9._-]+' | sort -u \
  | sed 's/^/  plugin: /' | head -20
printf '%s' "$PAGE" | grep -oE '/wp-content/themes/[a-z0-9._-]+' | sort -u \
  | sed 's/^/  theme:  /' | head -10

# --- REST namespaces: the quietest plugin disclosure there is ---
# Prefer /wp-json/; fall back to ?rest_route=/ (plain permalinks are common and
# make /wp-json/ 404). Only parse a real WordPress REST index; an HTML 404 page
# from a non-WordPress site would otherwise yield nav links as fake namespaces.
RESTIDX=""
if printf '%s' "$REST" | grep -q '"namespaces"'; then
  RESTIDX="$REST"
elif printf '%s' "$ROUTE" | grep -qE '"(namespaces|routes)"'; then
  RESTIDX="$ROUTE"
fi
if [ -n "$RESTIDX" ]; then
  # The index ships the plugin list as "namespaces":[...] with JSON-escaped
  # slashes ("wp\/v2"), so extract the array and strip the escapes rather than
  # pattern-matching route paths.
  printf '%s' "$RESTIDX" \
    | sed -n 's/.*"namespaces":\[\([^]]*\)\].*/\1/p' \
    | tr ',' '\n' | tr -d '"\\' | sed '/^$/d' | head -25 \
    | sed 's/^/  namespace: /'
else
  say "REST namespaces" "skipped (no WordPress REST index)"
fi

# --- other cheap surfaces ---
say "xmlrpc.php" "$(curl -sS -m 15 -o /dev/null -w '%{http_code}' "$BASE/xmlrpc.php" 2>/dev/null)"
# User enumeration: try pretty REST first, then ?rest_route= (plain permalinks).
USERS=$(get "$BASE/wp-json/wp/v2/users?per_page=100")
if ! printf '%s' "$USERS" | grep -q '"slug"'; then
  USERS=$(get "$BASE/?rest_route=/wp/v2/users&per_page=100")
fi
if printf '%s' "$USERS" | grep -q '"slug"'; then
  say "REST users" "enumerable: $(printf '%s' "$USERS" | grep -oE '"slug":"[^"]+"' | head -5 | tr '\n' ' ')"
else
  say "REST users" "not enumerable"
fi
say "uploads listing" "$(curl -sS -m 15 -o /dev/null -w '%{http_code}' "$BASE/wp-content/uploads/" 2>/dev/null)"

echo
echo "Next: read readme.txt/style.css per plugin slug for versions, then"
echo "      scripts/wp-cve-scan.sh $BASE  (version-gate the hits before reporting)."
