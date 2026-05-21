# Security Policy

## Supported versions

This project is a fork maintained out of `main`. Security fixes land on `main`
and are picked up by downstream consumers who track the branch. There is
currently no formal support window for older tags.

## Reporting a vulnerability

If you believe you've found a security issue in this server — token leaks,
remote tool invocation, MSP API misuse, prompt-injection sinks reaching the
agent, dependency CVEs reachable from runtime code — please report it
privately rather than opening a public issue.

Email: **zach.christensen@matesecurity.io**

Please include:

- A clear description of the issue and its impact.
- Reproduction steps or a proof-of-concept payload if you have one. For
  agent-level issues, a minimized MCP tool-call sequence is ideal.
- The commit SHA you reproduced against.
- Any suggested remediation, if you have one.

You should expect:

- An acknowledgement within one business day.
- A status update within five business days.
- A fix or a clear timeline within thirty days for high-severity issues; the
  same window for medium-severity unless coordination with upstream
  dependencies is required.

Please do not include private MSP tokens in your report. If reproduction
requires credentials, redact them — we don't need them to verify the issue.

## Out of scope

- Self-reported `npm audit` advisories on dev-tool transitives that don't
  reach the runtime. CI runs `npm audit --audit-level=high` against the
  runtime surface; transitives flagged by it are addressed routinely.
- Misconfiguration of operator-controlled environment variables that the
  documentation already warns against (e.g., setting `MCP_TEST_MODE=true`
  outside `NODE_ENV=production` — the server now refuses to start in that
  combination, but other operator-side misuses are not in scope).
- Findings in the upstream Firewalla MSP API itself; please report those to
  Firewalla.

## Threat model notes

The downstream consumer of this server is an AI security-investigation
agent, which means the agent's context window is itself a sensitive sink:

- Untrusted Firewalla data (device hostnames, DNS rdata, alarm messages)
  flows back to the agent as text. Report builders treat this data as
  prompt-injection-tainted and wrap it accordingly.
- HTTP transport (`MCP_TRANSPORT=http`) binds to `127.0.0.1` by default and
  validates `Host`/`Origin` headers. Operators who broaden the bind via
  `MCP_HTTP_HOST` should set `MCP_HTTP_BEARER` and put a TLS terminator in
  front; the server itself speaks plain HTTP.
- The MSP token is the crown-jewel secret. The logger redacts
  `Authorization`/`Bearer` patterns, axios errors have their headers
  defanged before any further handling, and `error.response.data` is
  never logged at debug level.

See `.omc/autopilot/security-audit-findings.md` (in-repo) for the full
findings list from the most recent audit, including severity ratings and
remediation status.
