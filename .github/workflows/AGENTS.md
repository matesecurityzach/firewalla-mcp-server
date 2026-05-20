<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# workflows

## Purpose
GitHub Actions workflow definitions.

## Key Files

| File | Description |
|------|-------------|
| `ci.yml` | Pull-request / push CI: install, typecheck, lint (zero warnings), build, test. |
| `docker-publish.yml` | Tag-driven multi-arch (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) Docker Hub publish. |

## For AI Agents

### Working In This Directory
- Keep job names stable — branch protection rules pin them.
- Docker push requires `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN` repository secrets.
- The CI gate mirrors `npm run ci:full` locally; reproduce failures with that command before pushing.

<!-- MANUAL: -->
