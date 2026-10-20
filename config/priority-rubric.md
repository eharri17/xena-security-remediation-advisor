# Priority rubric (PoC)

The advisor recommends a priority. A human reviewer always makes the final decision. Align the SLA column with your business unit's vulnerability management SLA before the pilot.

## Inputs

| Factor | Source | Values |
|---|---|---|
| Severity | Wiz | CRITICAL (only CRITICAL is in PoC scope) |
| Exploitability | Wiz (known exploit, CISA KEV, EPSS) | Known exploited / EPSS ≥ 0.5 / none known |
| Exposure | Wiz (internet exposure, network path, toxic combination) | Internet exposed / internal only |
| Environment | Wiz project, tags, account | Production / non-production |
| Business criticality | [ownership-map.yaml](ownership-map.yaml) | high / medium / low |
| Fix availability | Wiz (has fix, fixed version) | Fix available / no fix |

## Decision table

| Priority | Rule (first match wins) | Suggested SLA |
|---|---|---|
| **P1** | Production **and** internet exposed **and** (known exploited **or** EPSS ≥ 0.5) | 7 days |
| **P2** | Production **and** (internet exposed **or** known exploited **or** business criticality = high) | 15 days |
| **P3** | Production with no exposure or exploit signal, **or** non-production with known exploitation | 30 days |
| **P4** | Non-production with no exposure or exploit signal, **or** no fix available yet (track and mitigate) | 90 days / next maintenance window |

## Adjustments (state them explicitly in the draft)

- **No fix available**: Keep the priority, but recommend compensating controls such as WAF rules, network restriction, or feature disablement.
- **Historical precedent**: If a similar resolved issue in JIFA used a different priority, mention it as context. Don't override the table silently.
- **Unknown inputs**: Treat an `UNKNOWN` exposure or environment as the riskier value, and flag it for the reviewer.
