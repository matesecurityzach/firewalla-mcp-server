<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# scripts

## Purpose
One-off shell and Node scripts used for manual testing, demos, deployment, and dev environment setup. None are wired into `npm test` or CI; they are operator tools.

## Key Files

| File | Description |
|------|-------------|
| `comprehensive-test-plan.sh` | Manual end-to-end test plan script. |
| `demo-optimization.cjs` | Token-optimization demo, invoked by `npm run demo:optimization`. |
| `deploy.sh` | Deployment helper. |
| `dev-setup.sh` | Local dev environment setup. |
| `docker-publish.sh` | Manual Docker Hub publish (also automated via `.github/workflows/docker-publish.yml`). |
| `test-api-auth.js` | Sanity-check MSP token + box ID against the live API. |
| `test-problematic-tools.js` | Targeted exercising of tools known to have edge cases. |
| `test-rule-pause-resume-api.js` | Manual integration check for `pause_rule` / `resume_rule`. |

## For AI Agents

### Working In This Directory
- Scripts assume the working directory is the repo root.
- Anything calling the live API needs `.env` populated (`FIREWALLA_MSP_TOKEN`, `FIREWALLA_MSP_ID`).
- Don't put automated-CI logic here — that belongs in `.github/workflows/`.

### Common Patterns
- Mix of `bash` and `.cjs` / `.js` files (CommonJS for Node compatibility with no build step).

## Dependencies

### Internal
- Read live config via `dotenv` from project root.

<!-- MANUAL: -->
