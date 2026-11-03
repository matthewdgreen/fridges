# Are the fridges ok?

A static, sourced tracker of refrigeration cyberattacks and internet-exposed Danfoss StoreView services.

**Website:** https://matthewdgreen.github.io/fridges/

## Run locally

Requires Python 3.9+; no third-party dependencies or frontend build step.

```sh
python3 -m http.server 8765 --directory site
```

Open http://localhost:8765. Relative asset paths support GitHub project Pages under `/fridges/`.

## Daily updates

- **Shodan and deployment:** `.github/workflows/pages.yml` runs at 11:17 UTC daily, on manual dispatch, and on pushes to `main`. Scheduled/manual runs collect aggregates, validate, commit history, then publish `site/`. Push runs only validate and publish. GitHub may delay schedules.
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

**Services are not fridges.** Multiple ports can produce multiple Shodan results for one controller, while one controller can control many cabinets. Internet exposure does not establish exploitability or compromise. The query is a narrow StoreView fingerprint and does not cover every Danfoss product, the newer StoreView Web title, or Copeland/Dixell. Index data may be stale. We never query or scan discovered equipment.

The charts show individual observations, separated by collection type, with worldwide/France filters and a downloadable CSV. Published counts can differ because of search details and timing; do not interpret the points as an uninterrupted comparable series.

## Verify

```sh
python3 -m unittest discover -s tests -v
python3 scripts/validate.py
node --check site/app.js
```

Tests cover collection failures, missing keys, real zero counts, same-day deduplication, invalid API responses, query drift, and editorial data contracts. The page uses native disclosures, keyboard-operable region controls, an accessible data table, reduced-motion support, and responsive CSS.

## Sources

Each event and historical observation links to its evidence. Background: [CERT-FR advisory](https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/), [Censys November report](https://censys.com/blog/european-refrigerator-controller-redux-a-new-wave-of-refrigeration-attacks/), and [Shodan count API](https://developer.shodan.io/api#shodan-host-count).
