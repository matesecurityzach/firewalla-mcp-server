# Firewalla MCP Server

A Model Context Protocol (MCP) server that provides real-time access to Firewalla firewall data through 37 tools, designed for use by AI security-investigation agents and compatible with any MCP client.

> **Fork notice:** This repository is forked from [amittell/firewalla-mcp-server](https://github.com/amittell/firewalla-mcp-server) and has diverged. Changes in this fork focus on security hardening of the transport, validation, and logging layers (see recent commits). This fork is **not published to npm or Docker Hub** — install from source as described below.

## Why Firewalla MCP Server?

### Built for AI security investigations
- **37 tools**: 23 direct API endpoints, 5 convenience wrappers, **4 investigation composite tools** that correlate flows + alarms + rules + devices in one call, and **5 report composite tools** that return both structured data and a markdown narrative.
- **9 MCP resources**, including verified reference tables (`firewalla://reference/alarm-types`, `firewalla://reference/categories`, `firewalla://reference/query-syntax`) that let an agent ground its queries without crawling source.
- **Verified query grammar**: tool descriptions and validators reflect the actual Firewalla MSP qualifiers (`box.id`, `device.id`, `remote.region`, `transfer.total`, etc.) — not invented ones.
- **Agent investigation guide** (`docs/agent-investigation-guide.md`): playbooks, query cookbook, pagination and error patterns for building an investigation loop.

## Features

- **Real-time Firewall Data**: Query security alerts, network flows, and device status  
- **Security Analysis**: Get insights on threats, blocked attacks, and network anomalies  
- **Bandwidth Monitoring**: Track top bandwidth consumers and usage patterns  
- **Rule Management**: View and temporarily pause firewall rules  
- **Target Lists**: Manage custom security target lists and categories
- **Search Tools**: Query syntax with filters and logical operators

## Client Setup Guides

> The per-client guides under [docs/clients/](docs/clients/) were written against the upstream npm package. For this fork, replace any `npx firewalla-mcp-server` invocation with `node /absolute/path/to/firewalla-mcp-server/dist/server.js` (see [Connect Claude Desktop](#4-connect-claude-desktop) below).

| Client | Quick Start | Full Guide |
|--------|-------------|------------|
| **Claude Desktop** | Build from source → point `command` at `node dist/server.js` | [Setup Guide](docs/clients/claude-desktop.md) |
| **Claude Code** | Build from source → register via `claude mcp add` | [Setup Guide](docs/clients/claude-code.md) |
| **VS Code** | Install MCP extension → Configure server | [Setup Guide](docs/clients/vscode.md) |
| **Cursor** | Install Claude Code → VSIX method | [Setup Guide](docs/clients/cursor.md) |
| **Roocode** | Install MCP support → Configure server | [Setup Guide](docs/clients/roocode.md) |
| **Cline** | Configure in VS Code → Enable MCP | [Setup Guide](docs/clients/cline.md) |
  

## How It Works

```
Claude Desktop/Code ↔ MCP Server ↔ Firewalla API
```

The MCP server acts as a bridge between Claude and your Firewalla firewall, translating Claude's requests into Firewalla API calls and returning the results in a format Claude can understand.

## Prerequisites

- Node.js 18+ and npm
- Firewalla MSP account with API access
- Your Firewalla device online and connected

## Quick Start

### 1. Installation (from source)

This fork is distributed as source only.

```bash
git clone https://github.com/matesecurityzach/firewalla-mcp-server.git
cd firewalla-mcp-server
npm install
npm run build
```

After `npm run build`, the entry point is `dist/server.js`. Take note of the absolute path — you'll reference it from your MCP client config.

#### Optional: build a local Docker image

This fork is not published to a registry, but the included `Dockerfile` still works. Build and run locally:

```bash
docker build -t firewalla-mcp-server .

# Stdio (for Claude Desktop), reading credentials from a .env file
docker run -it --rm --env-file .env firewalla-mcp-server

# HTTP transport on port 3000
docker run -d --name firewalla-mcp \
  -p 3000:3000 \
  --env-file .env \
  -e MCP_TRANSPORT=http \
  -e MCP_HTTP_PORT=3000 \
  firewalla-mcp-server
```

> **Warning:** Passing `-e FIREWALLA_MSP_TOKEN=...` directly on the command line exposes the token to process listings and shell history. Prefer `--env-file .env` or Docker secrets.

### 2. Configuration

Create a `.env` file with your Firewalla credentials:

```env
# Required
FIREWALLA_MSP_TOKEN=your_msp_access_token_here
FIREWALLA_MSP_ID=yourdomain.firewalla.net

# Optional - filters all queries to a specific box
# FIREWALLA_BOX_ID=your_box_gid_here
```

**Getting Your Credentials:**
1. Log into your Firewalla MSP portal at `https://yourdomain.firewalla.net`
2. Your MSP ID is the full domain (e.g., `company123.firewalla.net`)
3. Generate an access token in API settings
4. (Optional) Find your Box GID in device settings to filter queries to a specific box, or retrieve available boxes using the `get_boxes` tool

#### Transport Configuration

The MCP server supports two transport modes:

**Stdio Transport (Default)**: Standard input/output communication for Claude Desktop and similar MCP clients
```env
MCP_TRANSPORT=stdio
```

**HTTP Transport**: HTTP server mode for Docker containers, MCP orchestrators, and external access
```env
MCP_TRANSPORT=http
MCP_HTTP_PORT=3000          # Default: 3000
MCP_HTTP_PATH=/mcp          # Default: /mcp
```

**When to use HTTP transport:**
- Running in Docker containers independently
- Accessing from MCP orchestrators (e.g., open-webui)
- Multiple clients need to connect to the same server instance
- Network-based access to the MCP server

**When to use stdio transport:**
- Claude Desktop integration (default)
- Claude Code CLI integration
- Single-process MCP client setups
- Standard MCP client configurations

### 3. Build and Start

```bash
npm run build
npm run mcp:start
```

### 4. Connect Claude Desktop

Add this configuration to your Claude Desktop `claude_desktop_config.json`, replacing `/full/path/to/firewalla-mcp-server` with the absolute path to your clone:

```json
{
  "mcpServers": {
    "firewalla": {
      "command": "node",
      "args": ["/full/path/to/firewalla-mcp-server/dist/server.js"],
      "env": {
        "FIREWALLA_MSP_TOKEN": "your_msp_access_token_here",
        "FIREWALLA_MSP_ID": "yourdomain.firewalla.net",
        "FIREWALLA_BOX_ID": "your_box_gid_here"
      }
    }
  }
}
```

If you built a local Docker image instead, point `command` at `docker` with `--env-file` so the token never appears in the config file:

```json
{
  "mcpServers": {
    "firewalla": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--env-file", "/full/path/to/.env", "firewalla-mcp-server"]
    }
  }
}
```

**Config file locations:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Connect Claude Code

From the cloned directory:

```bash
claude mcp add firewalla \
  -e FIREWALLA_MSP_TOKEN=your_token \
  -e FIREWALLA_MSP_ID=yourdomain.firewalla.net \
  -e FIREWALLA_BOX_ID=your_box_gid \
  -- node "$(pwd)/dist/server.js"
```

### 5. Next Steps

- See **[USAGE.md](USAGE.md)** for practical examples and common queries
- Check **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** if you encounter issues
- Review client-specific setup guides in [docs/clients/](docs/clients/)

## Usage Examples

### Step-by-Step First Use

**1. Verify Connection**
After completing the setup, verify the MCP server is working:

```bash
# Start the server
npm run mcp:start

# You should see output like:
# MCP Server starting...
# Firewalla client initialized
# Server ready on stdio transport
```

**2. Test with Claude**
Open Claude Desktop and try these starter queries:

**Basic Health Check:**
```text
"Can you check my Firewalla status and show me a summary?"
```
*This uses: `firewall_summary` resource + `get_simple_statistics` tool*

**Security Overview:**
```text
"What security alerts do I have? Show me the 5 most recent ones."
```
*This uses: `get_active_alarms` tool with limit parameter*

### Practical Workflows

**Daily Security Review:**
```text
"Give me today's security report. Include:
1. Any new security alerts
2. Top 3 devices using bandwidth
3. Any devices that went offline
4. Status of critical firewall rules"
```

**Investigating Suspicious Activity:**
```text
"I noticed unusual traffic. Can you:
1. Show me all security and abnormal upload alarms from the last 4 hours
2. Find any blocked connections to external IPs
3. Check which devices had the most network activity"
```

**Network Troubleshooting:**
```text
"A device seems to have connectivity issues. Can you:
1. Check if device 192.168.1.100 is online
2. Show its recent network flows
3. See if any rules are blocking its traffic"
```

**Bandwidth Investigation:**
```text
"Our internet is slow. Help me find the cause:
1. Show top 10 bandwidth users in the last hour
2. Look for any devices with unusual upload/download patterns
3. Check for any streaming or video traffic"
```

### Advanced Search Examples

**Find Specific Threats:**
```text
search for: security activity alarms from IP range 10.0.0.* in the last 24 hours
```
*Uses: `search_alarms` with query: "type:1 AND source_ip:10.0.0.* AND timestamp:>24h"*

**Analyze Rule Effectiveness:**
```text
"Show me firewall rules that blocked the most connections this week"
```
*Uses: `get_network_rules` + `search_flows` for blocked traffic analysis*

**Device Behavior Analysis:**
```text
"Find all devices that were online yesterday but are offline now"
```
*Uses: `search_devices` with temporal queries + `get_offline_devices`*


### Troubleshooting Common Issues

**Connection Problems:**
If you get authentication errors:
1. Verify your `.env` file has correct credentials
2. Check your MSP token hasn't expired
3. Confirm your Box ID is the full GID format

**Empty Results:**
If queries return no data:
1. Check your Firewalla is online and reporting
2. Verify the time range isn't too narrow
3. Try broader search terms first

**Performance Issues:**
If responses are slow:
1. Reduce the limit parameter in queries
2. Use more specific time ranges
3. Check your network connection to the MSP API

## Available Tools (37 total)

### Categories
- **Security (2)**: alarm retrieval (`get_active_alarms`, `get_specific_alarm`).
- **Network (3)**: `get_flow_data`, `get_bandwidth_usage`, `get_offline_devices`.
- **Device (1)**: `get_device_status`.
- **Rules (9)**: rule + target-list CRUD plus `get_network_rules_summary`.
- **Search (5)**: `search_flows`, `search_alarms`, `search_rules`, `search_devices`, `search_target_lists`.
- **Analytics (8)**: box/region stats, `get_flow_insights`, `get_recent_flow_activity`, `get_alarm_trends`, `get_rule_trends`.
- **Investigation composite (4)**: `investigate_ip`, `investigate_device`, `get_alarm_context`, `get_target_timeline`.
- **Report composite (5)**: `generate_security_report`, `generate_threat_analysis`, `generate_bandwidth_analysis_report`, `generate_device_investigation_report`, `generate_network_health_report`.

### Quick Reference
```
Security:       get_active_alarms, get_specific_alarm
Network:        get_flow_data, get_bandwidth_usage, get_offline_devices
Devices:        get_device_status, get_boxes, search_devices
Rules:          get_network_rules, get_network_rules_summary, pause_rule, resume_rule
Target lists:   get_target_lists, get_specific_target_list, create_target_list, update_target_list, delete_target_list, search_target_lists
Search:         search_flows, search_alarms, search_rules
Analytics:      get_simple_statistics, get_statistics_by_region, get_statistics_by_box,
                get_recent_flow_activity, get_flow_insights, get_alarm_trends, get_rule_trends
Investigation:  investigate_ip, investigate_device, get_alarm_context, get_target_timeline
Reports:        generate_security_report, generate_threat_analysis,
                generate_bandwidth_analysis_report, generate_device_investigation_report,
                generate_network_health_report
```

See `docs/agent-investigation-guide.md` for tool-selection playbooks and the verified query cookbook.

## Development

### Scripts

```bash
npm run dev          # Start development server with hot reload
npm run build        # Build TypeScript to JavaScript
npm run test         # Run all tests
npm run test:watch   # Run tests in watch mode
npm run lint         # Run ESLint
npm run lint:fix     # Fix ESLint issues
```

### MCP Execution Methods

Because this fork is source-only, the two supported execution paths are:

```bash
# Development: rebuild then run (picks up source changes)
npm run mcp:start

# Production: run the compiled entry point directly
node dist/server.js
```

The `node dist/server.js` form is what MCP client configs (Claude Desktop, Claude Code, VS Code, Cursor, etc.) should point at.

### Project Structure

```text
firewalla-mcp-server/
├── src/
│   ├── server.ts           # Main MCP server
│   ├── firewalla/          # Firewalla API client
│   ├── tools/              # MCP tool implementations
│   ├── resources/          # MCP resource implementations
│   └── prompts/            # MCP prompt implementations
├── tests/                  # Test files
├── docs/
│   └── firewalla-api-reference.md  # API documentation
├── CLAUDE.md              # Comprehensive development guide
├── SPEC.md                # Technical specifications
└── README.md              # This file
```

## Documentation

- **README.md** (this file) - Setup and basic usage
- **[USAGE.md](USAGE.md)** - Simple usage guide with examples
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues and solutions
- **docs/clients/** - Client-specific setup guides  
- **CLAUDE.md** - Development guide and commands

## Security

- MSP tokens are stored securely in environment variables
- No credentials are logged or stored in code
- Rate limiting prevents API abuse
- Input validation prevents injection attacks
- All API communications use HTTPS

## Known Behaviors and Limitations

### Category Classification
- **Flow Categories**: Many network flows may show as empty category ("") in the Firewalla API response. This is expected behavior - Firewalla categorizes traffic when it recognizes the domain/service (e.g., "av" for audio/video, "social" for social media).
- **Target List Categories**: Some target lists may show category as "unknown". This is normal for user-created or certain system lists.
- **Timeline**: Category classification happens at the Firewalla device level and may take time to build up meaningful categorization data.

### Data Characteristics
- **Response Sizes**: The `get_recent_flow_activity` tool returns up to 150 recent flows to stay within token limits. For larger datasets or historical analysis, use `search_flows` with time filters for more targeted queries.
- **Geographic Data**: IP geolocation is enriched by the MCP server and includes country, city, and risk scores when available.

### API Limitations
- **Alarm Deletion**: The `delete_alarm` tool may not actually delete alarms even though the Firewalla API returns a success response. This appears to be a limitation of the MSP API where delete operations return `{"message": "success", "success": true}` but the alarm remains in the system. This may be due to permission restrictions or API design.

## Troubleshooting

### Quick Fixes

**Server won't start:**
```bash
# Clean and rebuild
npm run clean
npm run build

# If build fails, try:
npm install
npm run build
```

**Authentication errors:**
- Check your MSP token is valid
- Verify Box ID format (long UUID)
- Confirm MSP domain is correct

**No data returned:**
- Try broader queries: "last week" vs "last hour"
- Check if Firewalla is online
- Test with: "show me basic statistics"

**Slow responses:**
- Add limits: "top 10 devices"
- Use shorter time ranges
- Restart the server

### Debug Mode

Enable detailed logging:
```bash
DEBUG=mcp:* npm run mcp:start
```

For more detailed troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## What's New

**Fork — security hardening:**
- HTTP transport: loopback bind by default, Host/Origin allowlist, optional bearer-token gate, per-session `Server` instances.
- Signed pagination cursors; tightened path, query, and protocol-path validation.
- Secret redaction in logs; defanged axios error payloads to avoid leaking response bodies / headers.
- `MCP_TEST_MODE` hardened so dummy credentials cannot accidentally reach production calls; env-var bound failures soften to warnings where safe.
- Dependency hygiene: bumped `axios` and `@modelcontextprotocol/sdk`, removed unused `axios-retry`.

**Agent-first redesign (inherited from upstream):**
- 37 tools (was 28) including 4 investigation composite tools and 5 report composite tools.
- New MCP reference resources: `firewalla://reference/alarm-types`, `firewalla://reference/categories`, `firewalla://reference/query-syntax`, and `firewalla://boxes`.
- ListResources and ListPrompts handlers added so agents can discover the surface.
- Tool descriptions rewritten against the verified Firewalla MSP query grammar (`box.id`, `device.id`, `remote.region`, `transfer.total`, ...); the misleading `gid:`, `bytes:`, bare `mac:`, `status:1` references have been removed.
- New `docs/agent-investigation-guide.md` documents playbooks, query cookbook, pagination, and error patterns.

## License

[MIT License](LICENSE)

## Support

For issues and questions:
- Check the [troubleshooting guide](CLAUDE.md#common-issues-and-solutions)
- Review the [technical specifications](SPEC.md)
- Open an issue on GitHub



---

## GitHub Repository

**Fork**: [https://github.com/matesecurityzach/firewalla-mcp-server](https://github.com/matesecurityzach/firewalla-mcp-server)
**Upstream**: [https://github.com/amittell/firewalla-mcp-server](https://github.com/amittell/firewalla-mcp-server)

### Quick Links
- [Issues](https://github.com/matesecurityzach/firewalla-mcp-server/issues)
- [Pull Requests](https://github.com/matesecurityzach/firewalla-mcp-server/pulls)
- [Actions](https://github.com/matesecurityzach/firewalla-mcp-server/actions)
- [Security](https://github.com/matesecurityzach/firewalla-mcp-server/security)

