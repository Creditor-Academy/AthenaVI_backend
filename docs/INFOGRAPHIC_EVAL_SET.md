# Infographic eval set (v1)

Scoring checklist for P2 exit. Thresholds locked in [`INFOGRAPHIC_MODE_PRD.md`](INFOGRAPHIC_MODE_PRD.md) §12.

**Owner:** TBD (assign before P2 exit)

| Gate | Pass bar |
|------|----------|
| Fidelity (text/numbers vs stored spec) | ≥ 80% (16/20) |
| Structure (layout matches content/archetype) | ≥ 75% (15/20) |
| Style (only briefs that asked for style; min 8) | ≥ 70% of those |
| Dense (8+ sections) | ≥ 3 in set; ≥ 2/3 fidelity |

If fidelity fails at density after clamping, escape hatch is **Option C** (server-rendered canvas) in [`IMAGE_GEN_COMPLETE.md`](IMAGE_GEN_COMPLETE.md) §11.3 — not endless prompt tuning.

Include briefs with **no style ask** to detect style convergence (every output looking the same).

## Briefs

Mark each axis Pass/Fail after generate. Use `formatId` / `archetypeHint` as suggested; omit style when “none”.

| # | Topic | Archetype | Format | Style ask | Dense? | Fid | Struct | Style |
|---|-------|-----------|--------|-----------|--------|-----|--------|-------|
| 1 | 4-step SaaS onboarding funnel | process | landscape | none | | | | n/a |
| 2 | Same funnel, portrait | process | portrait | none | | | | n/a |
| 3 | Agile sprint cycle (5 stages) | cycle | square | minimal flat | | | | |
| 4 | India vs China population (public stats OK) | comparison | landscape | none | | | | n/a |
| 5 | Free vs Pro vs Enterprise plan comparison | comparison | landscape | corporate | | | | |
| 6 | Company Q3 KPI cards (invented private metrics must be — or omitted if not supplied) | stats | square | none | | | | n/a |
| 7 | Climate milestones 1990–2025 | timeline | landscape | none | | | | n/a |
| 8 | Product launch timeline, playful | timeline | portrait | playful colorful | | | | |
| 9 | Org chart: CEO → 3 VPs → teams | hierarchy | portrait | none | | | | n/a |
| 10 | Pyramid of needs (5 levels) | hierarchy | square | hand-drawn | | | | |
| 11 | 8 tips for remote work | list | landscape | none | | | | n/a |
| 12 | Checklist: launch day tasks | list | portrait | corporate | | | | |
| 13 | Water cycle | cycle | landscape | none | | | | n/a |
| 14 | Hiring pipeline 6 stages | process | landscape | neon accents | | | | |
| 15 | Dense: 10-step manufacturing process | process | landscape | none | yes | | | n/a |
| 16 | Dense: 12 historical events | timeline | portrait | none | yes | | | n/a |
| 17 | Dense: 9 KPI metrics grid | stats | square | minimal | yes | | | |
| 18 | A/B test flows as parallel lanes | comparison | landscape | none | | | | n/a |
| 19 | No archetype hint — “explain photosynthesis simply” | auto | landscape | none | | | | n/a |
| 20 | Style-only ask — “make a bold Bauhaus-style stats poster about coffee” | stats | square | Bauhaus bold | | | | |

## Notes

- Prefer regenerating from stored spec (empty regenerate body) when checking fidelity stability.
- After a pixel tweak (“darker background”), confirm `request.pixelEdited === true` and that content regen-from-spec still works.
- Watch shared generate rate limit (default 30/hour) during dogfood.
