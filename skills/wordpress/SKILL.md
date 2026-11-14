---
name: wordpress
description: "Invoke this skill whenever the target is, or may be, a WordPress site — /wp-login.php, /wp-json/, /wp-admin/, wp-content/ or wp-includes/ in any asset path, a generator meta=WordPress tag, readme.html, or a REST route under ?rest_route=. It covers non-destructive fingerprinting of core, plugin and theme versions, mapping those versions onto the image's wordpress-tagged nuclei templates (about 1780 templates, 1200+ of them CVE templates), version-gated verification, and the WordPress-specific bug classes that actually pay: plugin auth bypass, LFI/RFI, SQLi through plugin parameters, REST user enumeration, unauthenticated options update, and xmlrpc amplification. Prefer this skill over ad-hoc guessing on any WordPress target."
---

# WordPress assessment (version-gated, template-backed)

Under an **authorized** engagement only, and only for the task's in-scope assets.
WordPress is the highest-volume CVE surface on the web, almost all of it in
**plugins and themes**, not core. The job of this skill is to turn "it is
WordPress" into a short list of *version-matched* CVE hypotheses and then prove
one of them — not to fire every template at the site.

## Hard gates (read before touching a target)

1. **Authorization**: the asset must already be in the task's scope. Finding
   `wp-login.php` does not extend scope.
2. **Program policy**: check for exclusions before testing. Many programs cap or
   exclude vulnerable-plugin testing, and treat the target as a shared host.
   Record the policy basis in the finding.
3. **No credential attacks by default.** `xmlrpc.php` and `/wp-login.php` brute
   force are out of scope unless the engagement says otherwise: they lock out
   real users, trip security plugins, and are the fastest way to get the client
   paged. `xmlrpc.php` amplification (`system.multicall`) is a *posture* note,
   not a thing to run at scale.
4. **No destructive payloads.** No `wp-config.php` overwrite, no plugin
   install/activate through an admin session you obtained, no option writes that
   change site behaviour. Read and prove; do not mutate.
5. **One-shot verification.** Prove execution/injection once with a marker,
   capture the request/response, stop. No webshell, no persistence.
6. **Rate discipline.** The scripts default low on purpose. Sites behind
   DDoS-Guard/Cloudflare rate-limit long before you finish; a `429`/`503` is a
   signal to slow down, never to raise the rate.

## Step 0 — confirm WordPress (cheap, passive)

```sh
BASE=https://target.example
curl -sS -m 15 -D - -o /dev/null "$BASE/" | grep -iE '^(server|x-powered-by)'
curl -sS -m 15 "$BASE/" | grep -oiE '<meta name="generator" content="[^"]*"' | head
curl -sS -m 15 -o /dev/null -w 'wp-login %{http_code} %{redirect_url}\n' "$BASE/wp-login.php"
curl -sS -m 15 -o /dev/null -w 'wp-json  %{http_code}\n' "$BASE/wp-json/"
curl -sS -m 15 -o /dev/null -w 'rest_api %{http_code}\n' "$BASE/?rest_route=/"
```

Signals: `wp-login.php` (200 or 302 to itself), `/wp-json/` returning JSON with
`"namespaces"`, `?rest_route=` working when pretty permalinks are off,
`wp-content/`/`wp-includes/` in any asset URL, a `generator` meta tag.

**Do not trust a single signal.** A `wp-login.php` 200 can be a decoy, and a
generic 403 from a WAF is not "not WordPress". Confirm with two independent
signals before spending budget.

## Step 1 — core version (passive first)

Core version normally comes from static assets, not the homepage:

```sh
curl -sS -m 15 "$BASE/" | grep -oE 'wp-(includes|content)/[^"?]+' | sort -u | head -20
curl -sS -m 15 "$BASE/readme.html" | grep -oiE 'Version [0-9.]+' | head -3
curl -sS -m 15 "$BASE/feed/" | grep -oiE '<generator>[^<]*' | head -3
```

If the version is hidden, move on to plugin enumeration instead of burning
budget guessing. `insert_assets` the version you *did* read, with its source, so
the next worker does not repeat the request.

## Step 2 — plugins and themes (no wpscan in this image)

There is **no `wpscan`, no `whatweb`, and no installed wordlist**. Do not waste a
turn discovering that. Harvest what the page already leaks, then confirm paths:

```sh
curl -sS -m 20 "$BASE/" | grep -oE '/wp-content/(plugins|themes)/[a-z0-9._-]+' | sort -u
katana -u "$BASE" -d 2 -silent -nc 2>/dev/null \
  | grep -oE '/wp-content/(plugins|themes)/[a-z0-9._-]+' | sort -u
```

Then read each slug's version:

```sh
while read -r slug; do
  for f in readme.txt style.css; do
    printf '%s/%s -> ' "$slug" "$f"
    curl -sS -m 10 -o /tmp/wp.$$ -w '%{http_code} ' "$BASE/wp-content/plugins/$slug/$f"
    grep -im1 -E '^Stable tag:|^Version:' /tmp/wp.$$ || echo '(no version)'
  done
done < slugs.txt
```

The REST API expands the surface cheaply — use it before fuzzing paths:

```sh
curl -sS -m 15 "$BASE/wp-json/" | head -c 2000            # namespaces == installed plugins
curl -sS -m 15 "$BASE/wp-json/wp/v2/users?per_page=100"   # author enumeration
curl -sS -m 15 -o /dev/null -w '%{http_code}\n' "$BASE/xmlrpc.php"
```

A namespace such as `/contact-form-7/v1` or `/yoast/v1` names the plugin
outright — cheaper and quieter than path fuzzing.

## Step 3 — map versions to CVEs (where the templates come from)

The image ships **projectdiscovery nuclei-templates** (currently v10.5.2,
~14,200 templates; **1,783 tagged `wordpress`**, **1,593 tagged `wp-plugin`**,
**1,217 of the wordpress set are CVE-named**, with CVE directories through the
current year). Templates *are* the CVE corpus — ARTEX ingests no separate CVE
database.

**Refresh first** — templates auto-install on first use and do not self-update
on a schedule:

```sh
nuclei -update-templates 2>&1 | tail -3
nuclei -tl -tags wordpress | wc -l
nuclei -tl -tags wordpress | grep -iE 'cve-20(25|26)' | head -20   # freshness check
```

Run detection **scoped to the confirmed technology**, critical/high first,
rate-limited, without out-of-band callbacks unless policy allows them:

```sh
nuclei -u "$BASE" -tags wordpress -severity critical,high \
       -rl 10 -c 10 -timeout 15 -retries 1 -no-interactsh -stats \
       -jsonl -o /tmp/wp-nuclei.jsonl
```

Rules for using the output:

- A template hit is a **lead**, not a finding. It proves the template's logic,
  not this asset's vulnerability.
- **Version-gate every CVE**: readme `2.7.1` with a fix in `2.7.2` is a
  candidate; a site on `2.8.0` is not. Never report a CVE the detected version
  already fixes.
- For a specific Candidate, run only its template
  (`-t http/cves/<year>/CVE-XXXX-YYYY.yaml`) instead of the whole tag set.
- Templates lag advisories by days to weeks. If the advisory is newer than the
  template set, pull it from the feed directly:

  ### Pull current CVEs from an authoritative source

  ```sh
  # last 30 days of WordPress CVEs, straight from NVD API 2.0 (no key needed)
  python3 scripts/wp_cve_fetch.py --days 30 --min-score 7

  # CVEs naming one plugin
  python3 scripts/wp_cve_fetch.py --plugin "Contact Form 7" --days 90

  # current release of core / a plugin, from the wordpress.org API
  python3 scripts/wp_cve_fetch.py --core
  python3 scripts/wp_cve_fetch.py --plugin-slug contact-form-7 --latest
  ```

  `wp_cve_fetch.py` retries NVD's 403/429/503 throttling and **exits non-zero when
  the feed is unreachable** — report that as a tool gap instead of recalling CVEs
  from memory. Set `NVD_API_KEY` to raise the limit (5 → 50 requests / 30 s).

  ### Gate the versions before anything else

  ```sh
  python3 scripts/wp_version_gap.py "$BASE"          # core + plugins found on the page
  python3 scripts/wp_version_gap.py "$BASE" --core 6.9.4 --plugin contact-form-7=5.8
  ```

  Exit code `2` means something is outdated, and the table pairs each detected
  version with the current release. **Only OUTDATED components make their CVE
  templates candidates.** The CVE text usually states the fixed version
  ("before 2.3.26", "up to and including 3.5.54") — compare that against the
  detected version before writing a finding.

## Step 4 — verify once, with evidence

For each surviving candidate, prove it with the minimum request that only
succeeds when the bug is real, and keep both request and response:

- **SQLi**: `sqlmap -u "<url with param>" --batch --level 2 --risk 1 --technique=BEUSTQ --dbs`, one parameter at a time.
- **LFI/RFI**: read a known file, or include a benign marker you control.
- **Auth bypass / missing capability check**: reach the privileged action
  unauthenticated and show the differing response vs. the 401/403 path.
- **RCE**: one marker command (`id`), then stop.

Record exact request, response excerpt, version evidence, and the template or
advisory behind the check. A version match alone is posture (`poe_level`), not a
verified finding.

## Step 5 — write back

- `insert_assets` for every host/slug/version confirmed (`tech` =
  `wordpress` or `wordpress-plugin:<slug>`).
- `record_fact` for what the next worker must not redo: core version + source,
  plugin/theme versions, REST namespaces, xmlrpc state, CDN/WAF in front,
  observed lockout behaviour.
- `report_finding` only with evidence: CVE id, affected and fixed versions,
  detected version, policy basis.
- If nothing was exploitable, say so with the version matrix — "fully patched"
  is a reportable result.

## Anti-patterns

| Don't | Why |
|---|---|
| Fire every `-tags wordpress` template at once | Noise, WAF ban, ~1,700 unverifiable hits |
| Report a CVE without checking the detected version | The top false-positive source in WordPress reports |
| Brute force `/wp-login.php` or `xmlrpc.php` | Locks out real users; out of scope by default |
| Read `readme.txt` 404 as "not installed" | Hardening removes it; confirm via asset paths or REST |
| Assume homepage plugin links are all plugins | Enumerate REST namespaces and crawled HTML too |
| Treat a WAF 403 as "patched" | A 403 is not evidence about a plugin's code |

## Environment notes

Present: `nuclei` (with templates), `httpx`, `ffuf`, `katana`, `sqlmap`,
`dalfox`, `nmap`, `bbot`, `curl`, `python3`.
Absent: `wpscan`, `whatweb`, `wp-cli`, and wordlists under `/usr/share/wordlists`.

Helpers in this skill's `scripts/` (run with the target base URL):

- `wp-fingerprint.sh <base-url>` — passive fingerprint; prints the version,
  plugin and namespace evidence lines to feed `insert_assets`.
- `wp_version_gap.py <base-url> [--core V] [--plugin slug=V]` — compares detected
  versions with the current releases from the wordpress.org API; exit `2` = outdated.
- `wp_cve_fetch.py [--days N] [--plugin NAME] [--core] [--latest --plugin-slug S]` —
  live CVE feed from NVD API 2.0 plus current versions from wordpress.org.
- `wp-cve-scan.sh <base-url> [severity]` — refreshes templates, then runs the
  wordpress-tagged set rate-limited into `/tmp/wp-nuclei.jsonl`.

Network endpoints this skill needs: `services.nvd.nist.gov`, `api.wordpress.org`,
`api.github.com` (nuclei template updates). All are outbound-only and send no
target data — only the plugin/keyword being looked up.
