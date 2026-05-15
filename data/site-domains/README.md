# Site-category reference data

Last refreshed: 2026-05-09. One base-domain per line, sorted, lowercase.

Wikidata-sourced files come from a SPARQL query selecting entities whose
`instance of` (P31) is the listed class and that publish an `official
website` (P856). Queries hit [QLever](https://qlever.cs.uni-freiburg.de/wikidata)
first (a faster public Wikidata mirror) and fall back to the official
[WDQS](https://query.wikidata.org/) endpoint if QLever is unavailable.
Wikidata data is CC0.

| File | Source | License |
|---|---|---|
| `bank.txt`            | Wikidata [Q22687](https://www.wikidata.org/wiki/Q22687) (bank) | CC0 |
| `retailer.txt`        | Wikidata [Q4830453](https://www.wikidata.org/wiki/Q4830453) (online shop) | CC0 |
| `news.txt`            | Wikidata [Q1110794](https://www.wikidata.org/wiki/Q1110794) (online newspaper) | CC0 |
| `airline.txt`         | Wikidata [Q46970](https://www.wikidata.org/wiki/Q46970) (airline) | CC0 |
| `university.txt`      | Wikidata [Q3918](https://www.wikidata.org/wiki/Q3918) (university) | CC0 |
| `social-media.txt`    | Union of Wikidata [Q3220391](https://www.wikidata.org/wiki/Q3220391) and [matomo-org/searchengine-and-social-list](https://github.com/matomo-org/searchengine-and-social-list) `Socials.yml` | CC0 |
| `search-engine.txt`   | matomo-org/searchengine-and-social-list `SearchEngines.yml` | CC0 |
| `ai-assistant.txt`    | matomo-org/searchengine-and-social-list `AIAssistants.yml` | CC0 |
| `popular.txt`         | Top 100000 of the [Tranco](https://tranco-list.eu/) list (aggregates CrUX, Farsight, Majestic, Cloudflare Radar, Umbrella) | Free for any use; cite if used in research |

## Refresh

```
bash scripts/refresh-domain-data.sh
```

## How to use

These files together form an allow-list of "known consumer / SaaS categories".
Anything not in any list defaults to "potentially corporate / unknown" — that's
the signal the Currentness Lab uses to decide whether a credential's site is
a recognised consumer service or something analyst-worthy.

`popular.txt` is the broad fallback. The category-specific files (`bank`,
`airline`, etc.) are useful when the lab needs to *label* a hit, not just
classify it as known/unknown.

## Notes

- Wikidata's coverage tracks notable entities; small regional banks or niche
  retailers may be missing. The lists are deliberately conservative — better
  to miss a consumer site than to mis-classify a corporate one.
- Domains are stored as the host published in the source. A lookup helper
  should also check the host's eTLD+1.
- A few categories were considered and dropped because their Wikidata QID
  has no items typed directly against it (the real items are typed under
  more specific subclasses): streaming media service (Q19757142), online
  dating service (Q1052158), cryptocurrency exchange (Q11154150), online
  gambling (Q9367093), online game platform (Q19097019). If we want these
  later, each needs a curated subclass list rather than a single P31 query.
- Refresh quarterly or whenever a new consumer category is needed.
