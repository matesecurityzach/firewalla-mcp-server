<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# prompts (tests)

## Purpose
Tests for `src/prompts/`. Covers `setupPrompts` registration (both `ListPrompts` and `GetPrompt` handlers) and `PROMPT_CATALOG` parity with the rendered list.

## Key Files

| File | Description |
|------|-------------|
| `index.test.ts` | Asserts that both `ListPromptsRequestSchema` and `GetPromptRequestSchema` handlers are registered, and that `ListPrompts` returns `PROMPT_CATALOG` verbatim. Behavior coverage for the underlying builders lives in `../tools/handlers/reports.test.ts`. |

<!-- MANUAL: -->
