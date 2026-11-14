#!/usr/bin/env python3
"""wp_version_gap.py - prove a WordPress component is actually OLD.

For an authorized target, read the versions the site exposes and compare them
with the current release from the WordPress.org API. This is the gate that keeps
a CVE template hit from becoming a false-positive finding: "the CVE is fixed in
2.7.2 and the site runs 2.8.0" means the hit does not apply.

Usage:
  wp_version_gap.py https://target.example                  # core + plugins found on the page
  wp_version_gap.py https://target.example --core 6.9.4 --plugin contact-form-7=5.8

Exit: 0 = ran, 1 = usage/network problem, 2 = something is outdated (details printed).
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "ARTEX-recon (+authorized pentest; version-gap)"
WPORG_PLUGIN = "https://api.wordpress.org/plugins/info/1.2/?"
WPORG_CORE = "https://api.wordpress.org/core/version-check/1.7/"


def get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def get_json(url, timeout=25):
    try:
        return json.loads(get(url, timeout))
    except Exception:                                   # noqa: BLE001
        return None


def ver_tuple(v):
    """Numeric tuple for comparison; non-numeric suffixes are dropped."""
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts[:4]) if parts else ()


def outdated(have, latest):
    a, b = ver_tuple(have), ver_tuple(latest)
    if not a or not b:
        return None                                     # unknown, do not guess
    return a < b


def detect_core(base):
    for path, pat in (
        ("/readme.html", r"Version\s+([0-9]+\.[0-9.]+)"),
        ("/", r'<meta name="generator" content="WordPress\s+([0-9.]+)"'),
    ):
        try:
            body = get(base + path)
        except Exception:                               # noqa: BLE001
            continue
        m = re.search(pat, body, re.I)
        if m:
            return m.group(1), path
    return None, None


def detect_plugins(base):
    """Slugs referenced by the rendered page, with version from readme/style if served."""
    try:
        page = get(base + "/")
    except Exception:                                   # noqa: BLE001
        return {}
    slugs = sorted(set(re.findall(r"/wp-content/plugins/([a-z0-9._-]+)/", page)))
    found = {}
    for slug in slugs:
        ver = None
        for path, pat in ((f"/wp-content/plugins/{slug}/readme.txt", r"Stable tag:\s*([0-9][0-9.]*)"),
                          (f"/wp-content/plugins/{slug}/style.css", r"Version:\s*([0-9][0-9.]*)")):
            try:
                m = re.search(pat, get(base + path), re.I)
            except Exception:                           # noqa: BLE001
                continue
            if m:
                ver = m.group(1)
                break
        found[slug] = ver
    return found


def latest_core():
    data = get_json(WPORG_CORE)
    if not data:
        return None
    offers = data.get("offers") or []
    return offers[0].get("current") if offers else None


def latest_plugin(slug):
    q = urllib.parse.urlencode({"action": "plugin_information", "request[slug]": slug})
    data = get_json(WPORG_PLUGIN + q)
    if not data or data.get("error"):
        return None
    return data.get("version")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--core", help="core version to check (default: detect from the target)")
    ap.add_argument("--plugin", action="append", default=[],
                    help="slug=version or slug (repeatable; overrides page scraping)")
    a = ap.parse_args()
    base = a.base.rstrip("/")

    rc = 0
    lc = latest_core()
    if lc is None:
        print("[!] wordpress.org core API unreachable - cannot gate core version")
        rc = 1

    core = a.core or detect_core(base)[0]
    if core and lc:
        flag = outdated(core, lc)
        state = "OUTDATED" if flag else ("current" if flag is False else "unknown")
        print(f"core            detected={core:<10} latest={lc:<10} {state}")
        if flag:
            rc = 2
    elif core:
        print(f"core            detected={core:<10} latest=???        unknown")
    else:
        print("core            not detected (readme.html/generator hidden)")

    plugins = {}
    for item in a.plugin:
        slug, _, ver = item.partition("=")
        plugins[slug] = ver or None
    if not plugins:
        plugins = detect_plugins(base)

    if not plugins:
        print("plugins         none referenced by the landing page; try katana crawl + REST namespaces")
    for slug, ver in sorted(plugins.items()):
        lp = latest_plugin(slug)
        if lp is None:
            print(f"plugin {slug:<24} detected={ver or '???':<10} latest=??? (not in wp.org dir)")
            continue
        if not ver:
            print(f"plugin {slug:<24} detected=???        latest={lp:<10} unknown (version hidden)")
            continue
        flag = outdated(ver, lp)
        state = "OUTDATED" if flag else ("current" if flag is False else "unknown")
        print(f"plugin {slug:<24} detected={ver:<10} latest={lp:<10} {state}")
        if flag:
            rc = 2 if rc == 0 else rc

    print("\nInterpretation: only OUTDATED components make their CVE templates "
          "candidates. A hit on a component at the fixed version or newer is a "
          "false positive for this asset.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
