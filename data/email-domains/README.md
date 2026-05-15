# Email-domain reference data

Last refreshed: 2026-05-09. One base-domain per line, sorted, lowercase.

| File | Source | License |
|---|---|---|
| `disposable.txt` | [disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) | CC0 |
| `free-providers.txt` | [Kikobeats/free-email-domains](https://github.com/Kikobeats/free-email-domains) minus the disposable overlap | MIT |

`free-providers.txt` deliberately excludes domains also listed in
`disposable.txt`, so it can be treated as "free / personal / ISP, **not**
disposable".

## Refresh

```
bash scripts/refresh-domain-data.sh
```
