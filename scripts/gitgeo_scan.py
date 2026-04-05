#!/usr/bin/env python3
"""
gitgeo_scan.py — subprocess wrapper called by supply-chain/geo-enricher.ts

Usage:
    python3 scripts/gitgeo_scan.py <owner/repo> [--max-contributors N]

Output: JSON to stdout
    {
      "repo": "owner/repo",
      "contributors_sampled": 20,
      "country_counts": { "United States": 12, "Germany": 3, ... },
      "top_country": "United States",
      "top_country_pct": 60.0,
      "concentration_score": 0.60,   // fraction held by top country (0.0–1.0)
      "unknown_pct": 15.0            // % of contributors with no location set
    }

Exits 0 always (errors written to stderr as JSON).
Requires env: GITHUB_TOKEN (optional but strongly recommended for rate limits)
"""

import json
import os
import sys
from collections import Counter

# Import only the modules that don't pull in folium
from gitgeo.github import get_contributors, get_contributor_location
from gitgeo.geolocation import get_country


def scan(repo: str, max_contributors: int = 20) -> dict:
    contributors = get_contributors(repo, max_num_contributors=max_contributors)

    country_counts: Counter = Counter()
    unknown = 0

    for user in contributors:
        location_str = get_contributor_location(user) or ""
        country = get_country(location_str) if location_str.strip() else None
        if country:
            country_counts[country] += 1
        else:
            unknown += 1

    total = len(contributors)
    known = total - unknown
    top_country, top_count = (
        country_counts.most_common(1)[0] if country_counts else (None, 0)
    )

    concentration = top_count / total if total > 0 else 0.0
    unknown_pct = (unknown / total * 100) if total > 0 else 0.0

    return {
        "repo": repo,
        "contributors_sampled": total,
        "country_counts": dict(country_counts),
        "top_country": top_country,
        "top_country_pct": round(top_count / known * 100, 1) if known > 0 else 0.0,
        "concentration_score": round(concentration, 3),
        "unknown_pct": round(unknown_pct, 1),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Scan GitHub repo contributor geography")
    parser.add_argument("repo", help="GitHub repo slug, e.g. owner/repo")
    parser.add_argument(
        "--max-contributors",
        type=int,
        default=20,
        help="Max contributors to sample (default: 20)",
    )
    args = parser.parse_args()

    if not os.environ.get("GITHUB_TOKEN"):
        print(
            json.dumps({"error": "GITHUB_TOKEN not set — rate limits will apply"}),
            file=sys.stderr,
        )

    try:
        result = scan(args.repo, max_contributors=args.max_contributors)
        print(json.dumps(result))
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": str(exc), "repo": args.repo}), file=sys.stderr)
        # Still exit 0 — the TypeScript bridge treats stderr errors as non-fatal
        sys.exit(0)


if __name__ == "__main__":
    main()
