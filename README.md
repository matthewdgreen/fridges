# Are the fridges ok?

A static, sourced tracker of refrigeration cyberattacks and internet-exposed Danfoss StoreView services.

**Website:** https://arethefridgesok.org/

## Run locally

Requires Python 3.9+; no third-party dependencies or frontend build step.

```sh
python3 -m http.server 8765 --directory site
```

Open http://localhost:8765. Relative asset paths support GitHub project Pages under `/fridges/`.

## Daily updates

- **Shodan and deployment:** `.github/workflows/pages.yml` runs at 11:17 UTC daily, on manual dispatch, and on pushes to `main`. Scheduled/manual runs collect distinct-IP, exposure and firmware aggregates, validate, commit their histories, then publish `site/`. Push runs only validate and publish. GitHub may delay schedules.
- **Credential:** the repository Actions secret `SHODAN_API_KEY` is configured. To replace it, run `gh secret set SHODAN_API_KEY --repo matthewdgreen/fridges` and enter it at the hidden prompt. Never put it in a file or command-line argument. The browser never receives the key.
- **News review:** the Codex heartbeat “Review fridge attacks daily” runs at 08:30 America/New_York. It searches and reads reports, makes evidenced editorial updates, and publishes them. It requires the local Codex environment to be available; GitHub collection continues independently. See `scripts/NEWS_REVIEW.md`.
- **Manual refresh:** `gh workflow run pages.yml --repo matthewdgreen/fridges`. Check the Actions run and published timestamp.
- **Failure behavior:** failed/missing-key requests preserve history and last-success timestamps. A failed request is published with an error state; the final workflow health job fails so it is visible in Actions. Missing credentials show pending, never a fabricated zero. The page marks measurements/reviews older than two UTC calendar days as stale/overdue.
- **Persistence:** one successful observation per UTC day; manual reruns replace that day's observation. No interpolation or invented historical data.

Pages is configured to deploy with Actions. The source repository can remain private while the published site is public, subject to the account's Pages eligibility.

## Data and definitions

- `site/data/status.json`: editorial yes/no assessment and last completed news review.
- `site/data/incidents.json`: sourced events. The counter uses the most recent `major: true` incident date, not its publication date. It measures elapsed UTC calendar days. Suspected US military events are explicitly unconfirmed and not attributed to Danfoss.
- `site/data/shodan.json`: direct daily samples of `http.title:"Danfoss StoreView"`, collected via Shodan's `/shodan/host/count` endpoint. Only totals and country facets are retained. No addresses, hosts, banners, or credentials are published.
- `site/data/reported-counts.json`: historical Shodan snapshots from SOCRadar and IRONHACKERS, kept distinct from direct collection. SOCRadar describes a page-title search without giving exact syntax; its methodology is not assumed identical to ours.
- `site/data/reviews.json`: completed news-review record.
- `site/data/hosts.json`: daily distinct-IP counts, with and without tagged service records, using cached Shodan IP facets.
- `site/data/versions.json`: daily service-weighted firmware inferences from cached HTTP headers.

**Services are not fridges.** Multiple ports can produce multiple Shodan results for one controller, while one controller can control many cabinets. Internet exposure does not establish exploitability or compromise. The query is a StoreView title fingerprint, not an inventory of every Danfoss product or Copeland/Dixell. In the baseline census it also matched newer StoreView Web titles; a supplemental StoreView Web query added no distinct services. Index data may be stale. Routine updates query cached index data only. Separately authorized manual measurements are documented below.

The charts show individual observations, separated by collection type, with worldwide/France filters and a downloadable CSV. Published counts can differ because of search details and timing; do not interpret the points as an uninterrupted comparable series.

## Verify

```sh
python3 -m unittest discover -s tests -v
python3 scripts/validate.py
node --check site/app.js
```

Tests cover collection failures, missing keys, real zero counts, same-day deduplication, invalid API responses, query drift, ambiguous fingerprints, changing index totals, overlapping counts, and editorial data contracts. The page uses native disclosures, keyboard-operable region controls, an accessible data table, reduced-motion support, and responsive CSS.

## Sources

Each event and historical observation links to its evidence. Background: [CERT-FR advisory](https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/), [Censys November report](https://censys.com/blog/european-refrigerator-controller-redux-a-new-wave-of-refrigeration-attacks/), and [Shodan count API](https://developer.shodan.io/api#shodan-host-count).

## Firmware mix over time

`site/data/versions.json` records daily worldwide service counts by inferred firmware. `python -m scripts.refresh_versions` queries only Shodan's `/shodan/host/count` endpoint, which consumes no search credits. It runs with the existing daily Actions job and secret. For a local collection, use `python3 -m scripts.refresh_versions --prompt-key` and enter the key at the hidden prompt.

The collector matches exact HTTP Last-Modified timestamps against [Censys's firmware-build mapping](https://censys.com/blog/frostbitten-in-france-a-danfoss-storeview-internet-exposure-report). It collects both the existing exposure query and the same query excluding Shodan-tagged honeypots. Multiple timestamps for one release are combined; a shared timestamp remains an ambiguous version family. Unknown/unmapped is the population total minus mapped fingerprints. Counts must be nonnegative and internally consistent. Shodan can return different totals for separate count requests (including requests with country facets). The firmware chart uses its own service-count snapshot; the headline uses the separate distinct-IP snapshot, and the exposure-history chart retains the separately collected unfiltered service series. Changing population totals or overlapping sums reject the snapshot; failures retain the last good history and fail the workflow health check after publication.

The page shows up to 30 daily observations as stacked bars, with percentage and absolute service-count modes, a honeypot filter, the latest exact-version table, and a complete CSV/JSON history download. The first baseline is explicitly not an upgrade trend. A rising share of 4.3.1 or 5.x can reflect upgrades, removals, arrivals, index changes, or a different mix of ports. It is not a measured per-device upgrade rate or a claim that newer equipment is secure. Untagged honeypots and duplicate physical devices may remain.

The source timestamps and query semantics are versioned as `storeview-last-modified-v1`. Do not silently change their meaning or reinterpret earlier samples; a changed measurement method needs a separate series or explicitly documented boundary.

### One-off full-result audit

`research/storeview-versions.json` preserves aggregate findings from the initial full paginated search. All 76 planned pages across the existing title query and a StoreView Web supplement were retrieved. Shodan returned 6,508 distinct services at 2,080 unique IPs, despite advertising 6,522 services; the coverage gap is recorded. The supplement overlapped the primary query completely. No addresses or raw banners were retained. Subsequent count-only queries covered the full advertised 6,522-service population and established the chart baseline.

The reproducible audit command is `python3 -m scripts.collect_versions --output research/storeview-versions.json`. Unlike the daily count-only collector, this consumes search credits and is **not scheduled**. It reads its key from the environment or a hidden prompt and requests cached results only. It does not connect to controllers or trigger scans.

The prominent baseline excludes Shodan-tagged honeypots and shows the inclusive total and excluded count in small print. A visible note explains the distinction before the metrics. If the filtered data cannot be loaded, the baseline is unavailable rather than silently replaced with an unfiltered total. Historical exposure points remain unfiltered and are labeled accordingly.

CSS and JavaScript asset URLs in `site/index.html` carry content-hash query values to avoid mixed cached releases. Refresh the corresponding SHA-256 prefix when editing these assets.

## One-off host deduplication and reachability measurement

`python3 -m scripts.measure_hosts` assembles distinct IPs from Shodan's existing IP facets and selects previously observed web endpoints from cached records. The optional `--live` flag makes at most one ordinary unauthenticated GET of `/` at one selected endpoint per eligible IP. This is an active reachability measurement, not a port or vulnerability scan, and is **not scheduled**.

The live phase uses at most six concurrent connections and starts no more than four IP checks per second. It does not retry or follow redirects, authenticate, fetch page resources, execute scripts, access control paths, or modify controller settings. It reads a bounded HTML prefix and headers. Non-public addresses, tagged-honeypot records, protocol-ambiguous endpoints, and cached organizations identifiable as military/defense are excluded from endpoint selection. Aggregate counts and inferred-version summaries are retained in `research/host-measurement.json` and published at `site/data/host-measurement.json`; raw addresses, page contents and credentials are not persisted. Do not rerun a live measurement merely to retry failed endpoints.

IP inventories are collected sequentially from a changing index, so partition totals can differ slightly. A distinct IP is a useful deduplication unit but may front multiple controllers. HTTP failures, redirects and TLS errors do not prove a device is offline. A visible StoreView version can identify the web UI rather than firmware; exact Last-Modified matches remain firmware inferences, not verified device versions or evidence of exploitation.

## Distinct-IP baseline

`site/data/hosts.json` is a separate history with unit **distinct IP addresses**, collected daily by `python3 -m scripts.refresh_hosts` using only Shodan's count endpoint and IP facets. It consumes no search credits and never contacts equipment. A complete facet directly gives the distinct-IP count. When the maximum-size facet is truncated but its smallest returned frequency is one, every omitted positive frequency must also be one; the remaining service count therefore gives the remaining distinct IPs. The collector rejects other truncated facets instead of guessing. The returned row and service sums and cardinality method are retained for audit.

The headline now uses distinct IPs with at least one matching service not tagged as a honeypot. The footnote shows all distinct IPs and the service-level totals. An IP with both flagged and unflagged service records can remain eligible; these are not certified real-controller counts. Older service observations and the service-weighted firmware distribution retain their original units and are explicitly labeled. A new unit is never retroactively substituted into the old time series.

The 3 November 2026 live measurement completed 2,050 requests: 212 recognizable StoreView pages, 1,409 timeouts, 332 TLS failures and 97 other outcomes. Of those recognized pages, 205 retained the cached firmware inference and seven differed or became unknown. No explicit UI-version text matched the limited HTML-prefix check; this does not establish that no version exists elsewhere. This sample is not a complete live fleet census or evidence of seven upgrades.
