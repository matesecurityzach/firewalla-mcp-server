# Agent Investigation Guide

This guide is for AI agents (or applications driving an AI agent) that use the
Firewalla MCP server to perform security investigations. It maps the tool
surface to investigation use cases, documents the verified query grammar, and
spells out the patterns that work well versus the ones that silently fail.

The companion files for an agent are:

- `docs/firewalla-api-reference.md` — verified MSP API spec (authoritative).
- `docs/query-syntax-guide.md` — full search-grammar reference.
- MCP resource `firewalla://reference/alarm-types` — the 1–16 type table.
- MCP resource `firewalla://reference/query-syntax` — qualifier tables.
- MCP resource `firewalla://reference/categories` — content categories.

---

## 1. Tool catalog (one line each)

### Discovery and inventory
- **`get_boxes`** — list every Firewalla box you can see; use first to anchor
  later `box.id:` filters.
- **`get_device_status`** — inventory of devices (online/offline, MAC, IP,
  network, group, byte counters).
- **`get_offline_devices`** — convenience wrapper around `get_device_status`
  filtered to offline devices, sorted by `lastSeen`.
- **`get_bandwidth_usage`** — top bandwidth consumers over a fixed period.

### Alarms (security signal)
- **`get_active_alarms`** — recent alarms, full payload including
  `device` + `remote` blocks. Best when you just want "what is firing".
- **`get_specific_alarm`** — fetch one alarm by `aid`. Used by
  `get_alarm_context`.
- **`search_alarms`** — query alarms with the MSP grammar. Use when you have
  a specific filter (type, region, device, transfer-volume).

### Flows (network signal)
- **`get_flow_data`** — direct passthrough to `/v2/flows`.
- **`get_recent_flow_activity`** — quick 50-flow snapshot. Do not use for
  historical analysis.
- **`search_flows`** — paginated flow search with the MSP grammar.
- **`get_flow_insights`** — category-based aggregation (top categories,
  bandwidth consumers, blocked traffic) without paginating.

### Rules and target lists
- **`get_network_rules`**, **`get_network_rules_summary`**,
  **`search_rules`** — read rules.
- **`pause_rule`**, **`resume_rule`** — write operations (rule lifecycle).
- **`get_target_lists`**, **`get_specific_target_list`**,
  **`create_target_list`**, **`update_target_list`**, **`delete_target_list`** —
  target-list CRUD.
- **`search_target_lists`** — client-side filtering over target lists.

### Aggregations and trends
- **`get_simple_statistics`** — global counts (boxes, alarms, rules).
- **`get_statistics_by_region`** — top regions by blocked flows.
- **`get_statistics_by_box`** — top boxes by blocked flows or security alarms.
- **`get_alarm_trends`**, **`get_rule_trends`** — daily-bucket trend series.

### Investigation composite tools (agent-first primitives)
- **`investigate_ip`** — flows + alarms + rules + device record for one IP.
- **`investigate_device`** — device dossier (record, alarms, flows, bandwidth,
  rules) for one device identifier (id / MAC / IP).
- **`get_alarm_context`** — alarm + related alarms grouped by same device /
  same remote IP / same remote domain / same type within a ±window.
- **`get_target_timeline`** — chronological event timeline (alarm | flow | rule
  entries) for a target (IP, domain, or device id).

### Report composite tools (agent-callable equivalents of MCP prompts)
- **`generate_security_report`** — composed firewall + alarms + threats payload
  plus narrative markdown.
- **`generate_threat_analysis`** — threat patterns, rule status, narrative.
- **`generate_bandwidth_analysis_report`** — bandwidth consumers + flow
  patterns + device stats + narrative. Requires `period`.
- **`generate_device_investigation_report`** — focused per-device dossier with
  narrative; requires `device_id`. For raw correlation without the narrative,
  prefer `investigate_device`.
- **`generate_network_health_report`** — full health snapshot + scores +
  narrative.

---

## 2. Verified query grammar

The MSP API parses queries server-side using the grammar in
`docs/firewalla-api-reference.md` (section "Search Functionality"). The local
parser additionally accepts `AND` / `OR` / `NOT` and `(` `)` grouping, which is
translated/forwarded transparently.

Verified rules:

- Space-separated terms intersect (implicit AND). `status:active type:1` is
  the same as `status:active AND type:1`.
- Prefix `-` to exclude. `-status:archived` removes archived alarms.
- Wildcards use `*`. `domain:*.facebook.com`, `device.ip:192.168.*`.
- Quoted values for whitespace, comma, asterisk, or colon. `box.name:"Gold Plus"`.
- Numeric comparisons with `>`, `>=`, `<`, `<=`. Data transfer units `B`, `KB`,
  `MB`, `GB`, `TB` (decimal). `transfer.total:>50MB`.
- Range form `a-b`. `ts:1695196894-1695604487`.

### Per-resource qualifier highlights

These come from the API reference and are the ones most useful in
investigations. The full table is in `firewalla://reference/query-syntax`.

| Resource | Qualifier | Notes |
| --- | --- | --- |
| flow | `direction`, `protocol`, `status` | `direction:outbound`, `protocol:tcp` |
| flow | `domain`, `region`, `category` | `region` is ISO-3166 (`region:CN`) |
| flow | `download`, `upload`, `total` | numeric with `B`/`KB`/`MB`/`GB`/`TB` |
| flow | `box.id`, `box.name`, `device.id`, `device.name`, `network.name` | `device.id:"mac:AA:BB:CC:DD:EE:FF"` |
| alarm | `type` (1-16) or `AlarmType:"..."` | see [alarm-types](#alarm-types) |
| alarm | `status:active` / `status:archived` | not `status:1`/`status:2` |
| alarm | `device.id`, `device.name`, `device.network.name` | |
| alarm | `remote.category`, `remote.domain`, `remote.region` | |
| alarm | `transfer.download`, `transfer.upload`, `transfer.total` | |
| rule | `status:active|paused`, `action:allow|block|timelimit` | |
| rule | `target.type`, `target.value`, `scope.type`, `scope.value` | |

### Things that look right but aren't

- `gid:` is **not** a verified MSP qualifier. Use `box.id:UUID`.
- `bytes:` is **not** a flow qualifier. Use `total`, `download`, or `upload`.
- `mac:AA:BB:...` (bare) is **not** a verified qualifier. Use
  `device.id:"mac:AA:BB:..."`. (The local client-side `search_devices` wrapper
  accepts a bare `mac:` field because it filters in-process; the API does not.)
- `severity:` is computed locally on alarms and is not a verified server
  qualifier. Querying by it works only because the handler post-processes the
  response.
- `resolved:` is not in the MSP API. Use `status:archived` to mean "resolved".

---

## 3. Investigation playbooks

Each playbook is a recommended tool sequence for an AI agent. Stick to the
investigation composite tools when possible — they bundle the correlation in
one call so you do not burn tokens on multi-step glue.

### Playbook A — Suspicious outbound traffic to a single IP

Question: "Device X is talking to 203.0.113.5. Is that interesting?"

1. `investigate_ip` with `ip="203.0.113.5"` and `lookback_hours=24`.
   - Inspect `summary.blocked_flow_count`, `summary.unique_remote_peers`,
     `summary.top_regions`.
   - If `device` is non-null the IP is one of yours.
2. If the result shows non-zero `alarm_count`, call `get_alarm_context` on
   the first alarm `aid` to find related alarms.
3. If you need to know whether other devices also talk to this IP, search:
   `search_flows` with `query="destination.ip:203.0.113.5"` and inspect
   distinct `device.id` values.
4. Decide: is there an existing rule? `search_rules` with
   `query="target.value:203.0.113.5"`. If not, create a `block` rule via
   `create_target_list` + a rule update.

### Playbook B — Possibly compromised device

Question: "Device `mac:AA:BB:CC:DD:EE:FF` is behaving oddly."

1. `investigate_device` with `device="mac:AA:BB:CC:DD:EE:FF"`,
   `lookback_hours=24`.
2. Look at `summary.top_categories` (porn/gamble/intel/p2p are red flags),
   `summary.top_regions` (unexpected geographies), and
   `summary.bytes.upload` (data exfiltration).
3. If alarms are present, call `get_alarm_context` on the top alarm.
4. For a human-readable narrative, call
   `generate_device_investigation_report` with the same `device_id`.

### Playbook C — Data exfiltration

Question: "Is anyone uploading lots of data right now?"

1. `search_flows` with `query="direction:outbound upload:>100MB"`,
   `limit=200`.
2. Group by device: take the result, count distinct
   `device.id` values, sort by total `upload`.
3. For the top device, run `investigate_device`.
4. For a structured deliverable, run `generate_bandwidth_analysis_report` with
   `period="24h"` and `threshold_mb=500`.

### Playbook D — Unknown new device on the network

Question: "Type 5 alarm: a new device appeared."

1. `get_alarm_context` with the new-device alarm `aid` and
   `window_seconds=3600`. Look for clustered new-device alarms (mass scan).
2. `search_devices` with `query="online:true name:*unknown*"` to enumerate
   unnamed devices.
3. `investigate_device` with the new device id for first-hour activity.

### Playbook E — Unusual geographic activity

Question: "Are we suddenly talking to a high-risk country?"

1. `get_statistics_by_region` to confirm the top regions by blocked flows.
2. `search_flows` with `query="region:CN direction:outbound total:>10MB"`
   (replace `CN` with the region of interest).
3. For any device IP that surfaces, run `investigate_ip`.
4. `get_target_timeline` with the suspicious remote IP to see how events
   ordered (rule push → flow → alarm vs. flow → alarm with no rule).

---

## 4. Pagination

All list/search endpoints return `next_cursor`. Honor it:

- Default `limit` is 200, maximum is 500.
- Pass the opaque `next_cursor` back via the `cursor` parameter.
- The MSP layer rate-limits at ~100 requests/minute per token. The MCP server
  caches GET responses for `CACHE_TTL` (default 300s; alarms/flows use 15s).
- For very large fan-outs (e.g. composite tools), the investigation primitives
  cap the per-resource pulls to keep the bundle response small. If you need
  exhaustive data, paginate `search_*` yourself.

---

## 5. Error handling for agents

Every tool returns a uniform error envelope:

```json
{
  "error": true,
  "message": "Parameter validation failed",
  "tool": "investigate_ip",
  "details": { "hint": "..." },
  "validation_errors": ["ip is required"]
}
```

Patterns:

- **Validation errors** (`error: true`, `validation_errors[...]`) — the
  parameters are wrong. Fix and retry.
- **Authentication errors** (HTTP 401 surfaced via the client) — the MSP token
  is invalid. Stop and surface to the user.
- **Rate limit** (HTTP 429) — back off. The internal axios-retry handles
  transient retries; if the error reaches you, wait at least 60 seconds.
- **Not found** (`get_specific_alarm`, `investigate_device`) — confirm the id
  format via the inventory tools (`get_active_alarms`, `get_device_status`,
  `search_devices`) before retrying with a different id.

When in doubt, fetch `firewalla://reference/query-syntax` and rebuild the
query against the verified qualifier tables.

---

## <a name="alarm-types"></a>Appendix — Alarm type quick reference

Also exposed at `firewalla://reference/alarm-types`.

| id | name | carries remote host? |
| --- | --- | --- |
| 1 | Security Activity | yes |
| 2 | Abnormal Upload | yes |
| 3 | Large Bandwidth Usage | no |
| 4 | Monthly Data Plan | no |
| 5 | New Device | no |
| 6 | Device Back Online | no |
| 7 | Device Offline | no |
| 8 | Video Activity | yes |
| 9 | Gaming Activity | yes |
| 10 | Porn Activity | yes |
| 11 | VPN Activity | no |
| 12 | VPN Connection Restored | no |
| 13 | VPN Connection Error | no |
| 14 | Open Port | no |
| 15 | Internet Connectivity Update | no |
| 16 | Large Upload | yes |
