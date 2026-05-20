<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# .github

## Purpose
GitHub Actions configuration. Holds workflow definitions and repository metadata.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `workflows/` | CI + Docker publishing workflows (see `workflows/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Branch protection assumes the CI workflow's job names — rename with care.
- Secrets used: Docker Hub credentials (publishing). Never echo secrets into job logs.

<!-- MANUAL: -->
