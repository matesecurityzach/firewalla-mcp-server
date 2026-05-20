/**
 * @fileoverview Static agent-facing reference resources.
 *
 * These resources expose verified Firewalla MSP API metadata as MCP resources
 * so investigation agents can resolve alarm-type ids, query qualifiers, and
 * content-category enumerations without crawling source code.
 *
 * URIs:
 * - firewalla://reference/alarm-types      Alarm type id->name table (1-16)
 * - firewalla://reference/query-syntax     Search grammar + per-resource qualifier table
 * - firewalla://reference/categories       Content category enumeration
 */

/**
 * Alarm type id-to-meaning table, verified against
 * docs/firewalla-api-reference.md (Alarm Model -> AlarmType enum).
 *
 * `remote` indicates whether the alarm carries a `remote` host block
 * (applies to types 1, 2, 8, 9, 10, 16 per the spec).
 */
export const ALARM_TYPES: ReadonlyArray<{
  id: number;
  name: string;
  description: string;
  remote: boolean;
}> = [
  {
    id: 1,
    name: 'Security Activity',
    description:
      'Generic security event. Carries device + remote host context; the highest-value type for AI threat triage.',
    remote: true,
  },
  {
    id: 2,
    name: 'Abnormal Upload',
    description:
      'Unusual outbound data volume from a device. Investigate for data exfiltration.',
    remote: true,
  },
  {
    id: 3,
    name: 'Large Bandwidth Usage',
    description:
      'Device crossed a bandwidth threshold (often informational, not malicious).',
    remote: false,
  },
  {
    id: 4,
    name: 'Monthly Data Plan',
    description: 'Monthly data plan usage threshold crossed.',
    remote: false,
  },
  {
    id: 5,
    name: 'New Device',
    description:
      'First-seen device on the network. Pair with investigate_device to triage.',
    remote: false,
  },
  {
    id: 6,
    name: 'Device Back Online',
    description: 'A previously-offline device reconnected.',
    remote: false,
  },
  {
    id: 7,
    name: 'Device Offline',
    description: 'A device went offline.',
    remote: false,
  },
  {
    id: 8,
    name: 'Video Activity',
    description: 'Device matched the video content category.',
    remote: true,
  },
  {
    id: 9,
    name: 'Gaming Activity',
    description: 'Device matched the gaming content category.',
    remote: true,
  },
  {
    id: 10,
    name: 'Porn Activity',
    description: 'Device matched the porn content category.',
    remote: true,
  },
  {
    id: 11,
    name: 'VPN Activity',
    description: 'VPN traffic observed.',
    remote: false,
  },
  {
    id: 12,
    name: 'VPN Connection Restored',
    description: 'VPN tunnel reconnected.',
    remote: false,
  },
  {
    id: 13,
    name: 'VPN Connection Error',
    description: 'VPN tunnel error.',
    remote: false,
  },
  {
    id: 14,
    name: 'Open Port',
    description: 'Open port detected. Investigate for unintended exposure.',
    remote: false,
  },
  {
    id: 15,
    name: 'Internet Connectivity Update',
    description: 'WAN status changed.',
    remote: false,
  },
  {
    id: 16,
    name: 'Large Upload',
    description:
      'Bulk outbound transfer. Investigate for exfiltration alongside type 2.',
    remote: true,
  },
];

/**
 * Content category enumeration, verified against the Flow Model -> Category
 * type in docs/firewalla-api-reference.md.
 */
export const CONTENT_CATEGORIES: ReadonlyArray<{
  name: string;
  description: string;
}> = [
  { name: 'ad', description: 'Advertising and trackers.' },
  { name: 'edu', description: 'Educational content.' },
  { name: 'games', description: 'Gaming services and platforms.' },
  { name: 'gamble', description: 'Gambling and betting sites.' },
  {
    name: 'intel',
    description:
      'Threat intelligence-flagged destinations (malware, phishing, C2). Highest investigation priority.',
  },
  { name: 'p2p', description: 'Peer-to-peer file sharing.' },
  { name: 'porn', description: 'Adult content.' },
  {
    name: 'private',
    description: 'Private/internal network destinations.',
  },
  { name: 'social', description: 'Social media platforms.' },
  { name: 'shopping', description: 'E-commerce.' },
  { name: 'video', description: 'Video streaming services.' },
  { name: 'vpn', description: 'VPN endpoints.' },
];

/**
 * Per-resource search qualifier tables, verified against the
 * "Search Qualifiers" section of docs/firewalla-api-reference.md.
 *
 * Only verified MSP API qualifiers are listed here. The local query parser
 * additionally accepts AND/OR/NOT grouping, ranges ([a TO b]), comparisons
 * (>=, <=, >, <), wildcards (*), and the "-qualifier:value" exclusion form.
 */
export const QUERY_QUALIFIERS = {
  flows: [
    { qualifier: 'ts', alias: '', description: 'Flow end timestamp (Unix).' },
    { qualifier: 'status', alias: '', description: 'Flow status (ok).' },
    {
      qualifier: 'direction',
      alias: '',
      description: 'inbound | outbound | local',
    },
    { qualifier: 'box.id', alias: '', description: 'Box GID (UUID).' },
    { qualifier: 'box.name', alias: 'Box', description: 'Box display name.' },
    {
      qualifier: 'box.group.id',
      alias: '',
      description: 'MSP group ID.',
    },
    {
      qualifier: 'device.id',
      alias: 'Mac',
      description: 'Device id (e.g. "mac:AA:BB:CC:DD:EE:FF").',
    },
    {
      qualifier: 'device.name',
      alias: 'Device',
      description: 'Device display name.',
    },
    {
      qualifier: 'network.id',
      alias: '',
      description: 'Device network identifier.',
    },
    {
      qualifier: 'network.name',
      alias: 'Network',
      description: 'Device network name (e.g. Guest).',
    },
    {
      qualifier: 'category',
      alias: 'Category',
      description: 'Content category. See firewalla://reference/categories.',
    },
    { qualifier: 'domain', alias: 'Domain', description: 'Remote domain.' },
    {
      qualifier: 'region',
      alias: 'Region',
      description: '2-letter ISO 3166 country code.',
    },
    { qualifier: 'sport', alias: 'SourcePort', description: 'Source port.' },
    {
      qualifier: 'dport',
      alias: 'DestinationPort',
      description: 'Destination port.',
    },
    {
      qualifier: 'download',
      alias: 'Download',
      description: 'Downloaded bytes (with B/KB/MB/GB/TB unit).',
    },
    {
      qualifier: 'upload',
      alias: 'Upload',
      description: 'Uploaded bytes (with B/KB/MB/GB/TB unit).',
    },
    {
      qualifier: 'total',
      alias: 'Total',
      description: 'Total transferred bytes (with B/KB/MB/GB/TB unit).',
    },
  ],
  alarms: [
    {
      qualifier: 'ts',
      alias: '',
      description: 'Alarm timestamp (Unix).',
    },
    {
      qualifier: 'type',
      alias: 'AlarmType',
      description:
        'Numeric (1-16) or named (e.g. AlarmType:"Security Activity"). See firewalla://reference/alarm-types.',
    },
    {
      qualifier: 'status',
      alias: '',
      description: 'active | archived',
    },
    { qualifier: 'box.id', alias: '', description: 'Box GID (UUID).' },
    { qualifier: 'box.name', alias: 'Box', description: 'Box display name.' },
    { qualifier: 'box.group.id', alias: '', description: 'MSP group ID.' },
    {
      qualifier: 'device.id',
      alias: 'Mac',
      description: 'Device id (e.g. "mac:AA:BB:CC:DD:EE:FF").',
    },
    {
      qualifier: 'device.name',
      alias: 'Device',
      description: 'Device display name.',
    },
    {
      qualifier: 'device.network.id',
      alias: '',
      description: 'Device network identifier.',
    },
    {
      qualifier: 'device.network.name',
      alias: 'Network',
      description: 'Device network name.',
    },
    {
      qualifier: 'remote.category',
      alias: 'Category',
      description:
        'Remote host category. See firewalla://reference/categories.',
    },
    {
      qualifier: 'remote.domain',
      alias: 'Domain',
      description: 'Remote domain.',
    },
    {
      qualifier: 'remote.region',
      alias: 'Region',
      description: '2-letter ISO 3166 country code.',
    },
    {
      qualifier: 'transfer.download',
      alias: 'Download',
      description: 'Downloaded bytes (with B/KB/MB/GB/TB unit).',
    },
    {
      qualifier: 'transfer.upload',
      alias: 'Upload',
      description: 'Uploaded bytes (with B/KB/MB/GB/TB unit).',
    },
    {
      qualifier: 'transfer.total',
      alias: 'Total',
      description: 'Total bytes transferred (with B/KB/MB/GB/TB unit).',
    },
  ],
  rules: [
    {
      qualifier: 'status',
      alias: '',
      description: 'active | paused',
    },
    {
      qualifier: 'action',
      alias: '',
      description: 'allow | block | timelimit',
    },
    { qualifier: 'box.id', alias: '', description: 'Box GID (UUID).' },
    { qualifier: 'box.group.id', alias: '', description: 'MSP group ID.' },
    {
      qualifier: 'device.id',
      alias: '',
      description: 'Device id (e.g. "AA:BB:CC:DD:EE:FF" or "mac:..." form).',
    },
  ],
} as const;

/**
 * Grammar cheat sheet.
 *
 * Mirrors the "Search Functionality" section of
 * docs/firewalla-api-reference.md and the additional locally-parsed forms
 * (AND/OR/NOT/parentheses/ranges/comparisons).
 */
export const QUERY_SYNTAX = {
  forms: [
    {
      form: 'literal',
      example: 'device.name:iphone',
      note: 'Exact / case-sensitive literal match.',
    },
    {
      form: 'list',
      example: 'category:social,video',
      note: 'Comma-separated list of literals.',
    },
    {
      form: 'wildcard',
      example: 'domain:*.facebook.com',
      note: 'Use * for fuzzy match. device.ip:192.168.* also valid.',
    },
    {
      form: 'quoted',
      example: 'box.name:"Gold Plus"',
      note: 'Wrap literals containing whitespace, commas, asterisks, or colons.',
    },
    {
      form: 'numeric comparison',
      example: 'transfer.total:>50MB',
      note: 'Supports >, >=, <, <=. Numeric data-transfer units: B|KB|MB|GB|TB.',
    },
    {
      form: 'range',
      example: 'ts:1695196894-1695604487',
      note: 'Numeric or timestamp range.',
    },
    {
      form: 'exclusion',
      example: '-status:archived',
      note: 'Prefix with - to exclude matches.',
    },
    {
      form: 'implicit AND',
      example: 'status:active type:1',
      note: 'Multiple space-separated terms intersect (AND).',
    },
    {
      form: 'AND/OR/NOT (local parser)',
      example: 'type:1 AND (remote.region:CN OR remote.region:RU)',
      note: 'The local query parser also accepts uppercase AND/OR/NOT and parentheses; these are translated/forwarded to the MSP query layer.',
    },
  ],
  units: [
    'B (byte)',
    'KB = 1000 B',
    'MB = 1000 KB',
    'GB = 1000 MB',
    'TB = 1000 GB',
  ],
  pagination: [
    'Most list/search endpoints return a cursor in next_cursor.',
    'Pass the cursor back via the cursor parameter to retrieve the next page.',
    'Default page size is 200; maximum is 500.',
  ],
  qualifiers: QUERY_QUALIFIERS,
} as const;
