#!/usr/bin/env python3
"""wp_cve_fetch.py - pull *current* WordPress CVE data from an authoritative feed.

Sources (no credentials required):
  NVD API 2.0        https://services.nvd.nist.gov/rest/json/cves/2.0
  WordPress.org API  https://api.wordpress.org/  (latest core/plugin versions)

Optional: set NVD_API_KEY in the environment to raise NVD's rate limit
(5 requests / 30 s without a key, 50 / 30 s with one).

Usage:
  wp_cve_fetch.py --days 30                     # recent WordPress CVEs
  wp_cve_fetch.py --plugin "Contact Form 7"     # CVEs naming that plugin
  wp_cve_fetch.py --plugin-slug contact-form-7 --latest   # latest version from wp.org
  wp_cve_fetch.py --core                        # latest WordPress core release

Design rule: never invent CVE data. If a source is unreachable after retries the
script says so and exits non-zero, so the agent reports a tool gap instead of
fabricating an advisory.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

UA = "ARTEX-recon (+authorized pentest; cve-fetch)"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def http_json(url, tries=4, timeout=40):
    headers = {"User-Agent": UA, "Accept": "application/json"}
    key = os.environ.get("NVD_API_KEY", "").strip()
    if key and "nvd.nist.gov" in url:
        headers["apiKey"] = key
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code in (403, 429, 503):       # NVD throttles hard; back off
                time.sleep(3 * (attempt + 1))
                continue
            break
        except Exception as e:                   # noqa: BLE001 - report, do not guess
            last = f"{type(e).__name__}: {e}"
            time.sleep(3 * (attempt + 1))
    print(f"[!] source unavailable: {url}\n    last error: {last}", file=sys.stderr)
    return None


def severity_of(cve):
    metrics = cve.get("metrics", {})
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(k, []) or []:
            d = m.get("cvssData", {})
            sev = (m.get("baseSeverity") or d.get("baseSeverity") or "").upper()
            score = d.get("baseScore")
            if score is not None:
                return sev or "?", float(score)
    return "?", None


def summarize(cve):
    desc = ""
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    sev, score = severity_of(cve)
    return {
        "id": cve.get("id", "?"),
        "published": (cve.get("published") or "")[:10],
        "severity": sev,
        "score": score,
        "desc": re.sub(r"\s+", " ", desc)[:260],
    }


def nvd_search(keyword, days, min_score, max_rows):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    rows = []
    index = 0
    while len(rows) < max_rows:
        q = {
            "keywordSearch": keyword,
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(100, max_rows - len(rows)),
            "startIndex": index,
        }
        data = http_json(NVD + "?" + urllib.parse.urlencode(q))
        if data is None:
            if rows:                             # keep what we already have
                print(f"[!] NVD throttled after {len(rows)} rows; showing partial results "
                      f"(raise the limit with NVD_API_KEY)", file=sys.stderr)
                break
            return None
        vulns = data.get("vulnerabilities", []) or []
        if not vulns:
            break
        for v in vulns:
            s = summarize(v["cve"])
            if min_score and (s["score"] is None or s["score"] < min_score):
                continue
            rows.append(s)
        index += len(vulns)
        if index >= int(data.get("totalResults", 0)):
            break
        time.sleep(6)                            # NVD public rate limit
    return rows


def print_rows(rows, header):
    print(f"\n{header}")
    print("-" * len(header))
    if not rows:
        print("(no matching CVEs in the requested window)")
        return
    for r in sorted(rows, key=lambda x: x["published"], reverse=True):
        score = f"{r['score']:.1f}" if r["score"] is not None else "  - "
        print(f"{r['published']}  {r['id']:<16} {r['severity']:<9} {score}  {r['desc']}")


def latest_core():
    data = http_json("https://api.wordpress.org/core/version-check/1.7/")
    if data is None:
        return None
    offers = data.get("offers", []) or []
    return offers[0].get("current") if offers else None


def latest_plugin(slug):
    q = urllib.parse.urlencode({"action": "plugin_information", "request[slug]": slug})
    data = http_json("https://api.wordpress.org/plugins/info/1.2/?" + q)
    if data is None:
        return None
    if data.get("error"):
        return {"error": data.get("error")}
    return {
        "slug": slug,
        "name": data.get("name"),
        "version": data.get("version"),
        "last_updated": (data.get("last_updated") or "")[:10],
        "active_installs": data.get("active_installs"),
        "closed": data.get("closed"),
    }


def main():
    p = argparse.ArgumentParser(description="Fetch current WordPress CVE / version data")
    p.add_argument("--days", type=int, default=30, help="publication window for NVD (default 30)")
    p.add_argument("--keyword", default="wordpress", help="NVD keyword (default: wordpress)")
    p.add_argument("--plugin", help='NVD keyword for one plugin, e.g. "Contact Form 7"')
    p.add_argument("--plugin-slug", help="wordpress.org slug, for --latest")
    p.add_argument("--latest", action="store_true", help="print the latest wp.org version for --plugin-slug")
    p.add_argument("--core", action="store_true", help="print the latest WordPress core version")
    p.add_argument("--min-score", type=float, default=0.0, help="minimum CVSS base score")
    p.add_argument("--max", type=int, default=60, help="max rows (default 60)")
    a = p.parse_args()

    rc = 0
    if a.core:
        v = latest_core()
        if v is None:
            rc = 2
        else:
            print(f"latest WordPress core: {v}")

    if a.latest and a.plugin_slug:
        info = latest_plugin(a.plugin_slug)
        if info is None:
            rc = 2
        elif info.get("error"):
            print(f"{a.plugin_slug}: not in the wordpress.org directory ({info['error']})")
        else:
            print(f"{info['slug']}: latest={info['version']} last_updated={info['last_updated']} "
                  f"installs={info.get('active_installs')} closed={info.get('closed')}")

    if not (a.core or (a.latest and a.plugin_slug)):
        kw = a.plugin or a.keyword
        rows = nvd_search(kw, a.days, a.min_score, a.max)
        if rows is None:
            print("\n[!] NVD unreachable - report this as a tool gap; do NOT infer CVEs from memory.", file=sys.stderr)
            return 2
        print_rows(rows, f'NVD: keyword="{kw}" published in the last {a.days} days'
                        + (f", CVSS >= {a.min_score}" if a.min_score else ""))
        print("\nNext: version-gate each CVE against the detected plugin/core version "
              "before treating it as a finding (see scripts/wp_version_gap.py).")

    return rc


if __name__ == "__main__":
    sys.exit(main())
