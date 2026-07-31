import React, { useState, useMemo, useEffect } from "react";

/* ---------------------------------------------------------
   Design tokens
--------------------------------------------------------- */
const C = {
  bg: "#0a0e14",
  bgGrad: "linear-gradient(180deg, #0a0e14 0%, #0d1420 100%)",
  panel: "#131a24",
  panel2: "#0f1720",
  border: "#1e2a3a",
  borderSoft: "#19232f",
  text: "#e2e8f4",
  muted: "#6b7d94",
  faint: "#3d4f63",
  teal: "#1ec2ac",
  tealSoft: "rgba(30,194,172,0.13)",
  amber: "#f0962a",
  amberSoft: "rgba(240,150,42,0.13)",
  violet: "#8b72e8",
  violetSoft: "rgba(139,114,232,0.14)",
  danger: "#e05470",
  dangerSoft: "rgba(224,84,112,0.12)",
  blue: "#5fa8f5",
  blueSoft: "rgba(95,168,245,0.13)",
  pink: "#e07bc2",
  green: "#7dce6a",
  greenSoft: "rgba(125,206,106,0.13)",
};

/* ---------------------------------------------------------
   IPv4 helpers & Class/Scope Detection
--------------------------------------------------------- */
function isValidIPv4(ip) {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return false;
  return parts.every(
    (p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255,
  );
}
function ipToInt(ip) {
  const p = ip.trim().split(".").map(Number);
  return (p[0] * 16777216 + p[1] * 65536 + p[2] * 256 + p[3]) >>> 0;
}
function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(
    ".",
  );
}
function cidrToMaskInt(cidr) {
  if (cidr <= 0) return 0;
  if (cidr >= 32) return 0xffffffff >>> 0;
  return (0xffffffff << (32 - cidr)) >>> 0;
}
function ipBinaryOctets(ip) {
  return ip
    .trim()
    .split(".")
    .map(Number)
    .map((n) => n.toString(2).padStart(8, "0"));
}

function detectIPv4ClassAndScope(ip) {
  if (!isValidIPv4(ip))
    return { classType: "Unknown", scope: "Invalid", color: C.muted, desc: "" };
  const p = ip.trim().split(".").map(Number);
  const first = p[0];
  const ipNum = ipToInt(ip);

  let classType = "Class A";
  let classColor = C.teal;
  if (first >= 128 && first <= 191) {
    classType = "Class B";
    classColor = C.blue;
  } else if (first >= 192 && first <= 223) {
    classType = "Class C";
    classColor = C.violet;
  } else if (first >= 224 && first <= 239) {
    classType = "Class D (Multicast)";
    classColor = C.pink;
  } else if (first >= 240 && first <= 255) {
    classType = "Class E (Experimental)";
    classColor = C.faint;
  }

  let scope = "Public Unicast";
  let scopeColor = C.green;
  let desc = "Globally routable public IPv4 address.";

  if (first === 127) {
    scope = "Loopback";
    scopeColor = C.amber;
    desc = "Host loopback address (RFC 1122).";
  } else if (first === 10) {
    scope = "Private (RFC 1918)";
    scopeColor = C.amber;
    desc = "10.0.0.0/8 private network space.";
  } else if (first === 172 && p[1] >= 16 && p[1] <= 31) {
    scope = "Private (RFC 1918)";
    scopeColor = C.amber;
    desc = "172.16.0.0/12 private network space.";
  } else if (first === 192 && p[1] === 168) {
    scope = "Private (RFC 1918)";
    scopeColor = C.amber;
    desc = "192.168.0.0/16 private network space.";
  } else if (first === 169 && p[1] === 254) {
    scope = "APIPA / Link-Local";
    scopeColor = C.violet;
    desc = "Auto-configured IP (RFC 3927).";
  } else if (first === 100 && p[1] >= 64 && p[1] <= 127) {
    scope = "Carrier-Grade NAT";
    scopeColor = C.blue;
    desc = "Shared transition space (RFC 6598).";
  } else if (first >= 224 && first <= 239) {
    scope = "Multicast Group";
    scopeColor = C.pink;
    desc = "IPv4 multicast traffic.";
  } else if (ipNum === 0xffffffff) {
    scope = "Limited Broadcast";
    scopeColor = C.danger;
    desc = "Local subnet broadcast.";
  }

  return { classType, scope, classColor, scopeColor, desc };
}

function calcIPv4Subnet(ip, cidr) {
  const ipInt = ipToInt(ip);
  const maskInt = cidrToMaskInt(cidr);
  const networkInt = (ipInt & maskInt) >>> 0;
  const wildcardInt = ~maskInt >>> 0;
  const broadcastInt = (networkInt | wildcardInt) >>> 0;
  const totalAddresses = Math.pow(2, 32 - cidr);
  let usableHosts, firstHostInt, lastHostInt;
  if (cidr >= 31) {
    usableHosts = cidr === 31 ? 2 : 1;
    firstHostInt = networkInt;
    lastHostInt = broadcastInt;
  } else {
    usableHosts = totalAddresses - 2;
    firstHostInt = networkInt + 1;
    lastHostInt = broadcastInt - 1;
  }
  return {
    network: intToIp(networkInt),
    broadcast: intToIp(broadcastInt),
    mask: intToIp(maskInt),
    wildcard: intToIp(wildcardInt),
    firstHost: intToIp(firstHostInt),
    lastHost: intToIp(lastHostInt),
    totalAddresses,
    usableHosts,
  };
}

/* ---------------------------------------------------------
   VLSM & FLSM helpers
--------------------------------------------------------- */
function calculateVLSM(baseIp, baseCidr, requirements) {
  const maskInt = cidrToMaskInt(baseCidr);
  const baseNetworkInt = (ipToInt(baseIp) & maskInt) >>> 0;
  const baseBroadcastInt = (baseNetworkInt | (~maskInt >>> 0)) >>> 0;
  const withOrder = requirements.map((r, i) => ({ ...r, _order: i }));
  const sorted = [...withOrder].sort((a, b) => b.hosts - a.hosts);
  let current = baseNetworkInt;
  const allocated = [];
  let error = null;
  for (const req of sorted) {
    const hostsNeeded = Math.max(0, Number(req.hosts) || 0);
    const hostBits = Math.max(0, Math.ceil(Math.log2(hostsNeeded + 2)));
    const blockSize = Math.pow(2, hostBits);
    const offsetFromBase = current - baseNetworkInt;
    const alignedOffset = Math.ceil(offsetFromBase / blockSize) * blockSize;
    const networkInt = baseNetworkInt + alignedOffset;
    const broadcastInt = networkInt + blockSize - 1;
    if (broadcastInt > baseBroadcastInt) {
      error = `Not enough address space for "${req.name}" (needs ${blockSize} addresses).`;
      break;
    }
    const newCidr = 32 - hostBits;
    allocated.push({
      _order: req._order,
      name: req.name,
      hostsRequested: hostsNeeded,
      network: intToIp(networkInt),
      cidr: newCidr,
      broadcast: intToIp(broadcastInt),
      firstHost: intToIp(hostBits === 0 ? networkInt : networkInt + 1),
      lastHost: intToIp(hostBits === 0 ? broadcastInt : broadcastInt - 1),
      usableHosts: hostBits === 0 ? 1 : Math.max(0, blockSize - 2),
      blockSize,
    });
    current = broadcastInt + 1;
  }
  allocated.sort((a, b) => a._order - b._order);
  return { allocated, error };
}

function calculateFLSM(baseIp, baseCidr, numSubnetsRequested) {
  const baseMaskInt = cidrToMaskInt(baseCidr);
  const baseNetworkInt = (ipToInt(baseIp) & baseMaskInt) >>> 0;
  const baseBroadcastInt = (baseNetworkInt | (~baseMaskInt >>> 0)) >>> 0;

  const count = Math.max(1, Math.min(256, Number(numSubnetsRequested) || 1));
  const addedBits = Math.ceil(Math.log2(count));
  const newCidr = baseCidr + addedBits;

  if (newCidr > 32) {
    return {
      allocated: [],
      newCidr,
      error: `Cannot divide /${baseCidr} into ${count} subnets (exceeds /32).`,
    };
  }

  const hostBits = 32 - newCidr;
  const blockSize = Math.pow(2, hostBits);
  const actualSubnetCount = Math.pow(2, addedBits);

  const allocated = [];
  for (let i = 0; i < actualSubnetCount; i++) {
    const netInt = baseNetworkInt + i * blockSize;
    const bcastInt = netInt + blockSize - 1;
    if (bcastInt > baseBroadcastInt) break;

    const usable =
      newCidr >= 31 ? (newCidr === 31 ? 2 : 1) : Math.max(0, blockSize - 2);
    const firstHostInt = newCidr >= 31 ? netInt : netInt + 1;
    const lastHostInt = newCidr >= 31 ? bcastInt : bcastInt - 1;

    allocated.push({
      index: i + 1,
      name: `Subnet #${i + 1}`,
      network: intToIp(netInt),
      cidr: newCidr,
      broadcast: intToIp(bcastInt),
      mask: intToIp(cidrToMaskInt(newCidr)),
      firstHost: intToIp(firstHostInt),
      lastHost: intToIp(lastHostInt),
      usableHosts: usable,
      blockSize,
    });
  }

  return { allocated, newCidr, actualSubnetCount, error: null };
}

/* ---------------------------------------------------------
   IPv6 helpers
--------------------------------------------------------- */
function expandIPv6(address) {
  const trimmed = address.trim();
  let groups;
  if (trimmed.includes("::")) {
    const [head, tail] = trimmed.split("::");
    const headGroups = head ? head.split(":").filter(Boolean) : [];
    const tailGroups = tail ? tail.split(":").filter(Boolean) : [];
    const missing = 8 - headGroups.length - tailGroups.length;
    groups = [
      ...headGroups,
      ...Array(Math.max(missing, 0)).fill("0"),
      ...tailGroups,
    ];
  } else {
    groups = trimmed.split(":");
  }
  while (groups.length < 8) groups.push("0");
  return groups.slice(0, 8).map((g) => g.padStart(4, "0"));
}
function ipv6ToBigInt(groups) {
  return groups.reduce(
    (acc, g) => (acc << 16n) + BigInt(parseInt(g, 16) || 0),
    0n,
  );
}
function bigIntToIPv6Groups(big) {
  const groups = [];
  for (let i = 0; i < 8; i++) {
    const shift = BigInt((7 - i) * 16);
    groups.push(((big >> shift) & 0xffffn).toString(16).padStart(4, "0"));
  }
  return groups;
}
function compressIPv6(groups) {
  let bestStart = -1,
    bestLen = 0,
    curStart = -1,
    curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === "0000") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  const trimmed = groups.map((g) => g.replace(/^0+(?=.)/, ""));
  if (bestLen > 1) {
    const before = trimmed.slice(0, bestStart).join(":");
    const after = trimmed.slice(bestStart + bestLen).join(":");
    return `${before}::${after}`;
  }
  return trimmed.join(":");
}
function calcIPv6Subnet(ip6, prefix) {
  const groups = expandIPv6(ip6);
  const ipBig = ipv6ToBigInt(groups);
  const hostBits = 128 - prefix;
  const mask = ((1n << BigInt(prefix)) - 1n) << BigInt(hostBits);
  const networkBig = ipBig & mask;
  const totalAddresses = 1n << BigInt(hostBits);
  const lastBig = networkBig + totalAddresses - 1n;
  return {
    groups,
    expanded: groups.join(":"),
    compressed: compressIPv6(groups),
    networkAddress: compressIPv6(bigIntToIPv6Groups(networkBig)),
    lastAddress: compressIPv6(bigIntToIPv6Groups(lastBig)),
    hostBits,
    totalAddresses: totalAddresses.toString(),
  };
}

function detectIPv6AddressType(groups) {
  const big = ipv6ToBigInt(groups);
  if (big === 0n)
    return {
      type: "Unspecified",
      scope: "N/A",
      color: C.muted,
      description: "Unspecified address.",
      rfc: "RFC 4291",
    };
  if (big === 1n)
    return {
      type: "Loopback",
      scope: "Host",
      color: C.teal,
      description: "Loopback address (::1).",
      rfc: "RFC 4291",
    };

  const first16 = (big >> 112n) & 0xffffn;
  const first8 = (big >> 120n) & 0xffn;
  const first10bits = (big >> 118n) & 0x3ffn;
  const first7bits = (big >> 121n) & 0x7fn;

  if (first8 === 0xffn)
    return {
      type: "Multicast",
      scope: "Multicast",
      color: C.pink,
      description: "Multicast address.",
      rfc: "RFC 4291",
    };
  if (first10bits === 0x3fan || (first16 >= 0xfe80n && first16 <= 0xfebfn))
    return {
      type: "Link-Local Unicast",
      scope: "Link",
      color: C.amber,
      description: "Local link auto-configured address.",
      rfc: "RFC 4291",
    };
  if (first7bits === 0x7dn || first7bits === 0x7en)
    return {
      type: "Unique Local (ULA)",
      scope: "Private",
      color: C.violet,
      description: "Private IPv6 network address.",
      rfc: "RFC 4193",
    };
  if (big >> 96n === 0x20010db8n)
    return {
      type: "Documentation",
      scope: "N/A",
      color: C.faint,
      description: "Documentation example address.",
      rfc: "RFC 3849",
    };
  if (big >> 125n === 1n)
    return {
      type: "Global Unicast",
      scope: "Global",
      color: C.teal,
      description: "Publicly routable unicast address.",
      rfc: "RFC 4291",
    };

  return {
    type: "Reserved / Special",
    scope: "N/A",
    color: C.muted,
    description: "Reserved IPv6 range.",
    rfc: "RFC 4291",
  };
}

function calcIPv6SubPrefixes(baseAddr, basePrefix, requirements) {
  let groups;
  try {
    groups = expandIPv6(baseAddr);
  } catch {
    return { allocated: [], error: "Invalid base IPv6 address." };
  }
  const baseBig = ipv6ToBigInt(groups);
  const hostBits = 128 - basePrefix;
  const baseMask = ((1n << BigInt(basePrefix)) - 1n) << BigInt(hostBits);
  const baseNetBig = baseBig & baseMask;
  const baseLastBig = baseNetBig + (1n << BigInt(hostBits)) - 1n;

  const withOrder = requirements.map((r, i) => ({ ...r, _order: i }));
  const sorted = [...withOrder].sort(
    (a, b) => Number(a.prefix) - Number(b.prefix),
  );
  let current = baseNetBig;
  const allocated = [];
  let error = null;

  for (const req of sorted) {
    const subPrefix = Number(req.prefix);
    if (subPrefix <= basePrefix || subPrefix > 128) {
      error = `Sub-prefix /${subPrefix} invalid for base /${basePrefix}.`;
      break;
    }
    const subHostBits = 128 - subPrefix;
    const blockSize = 1n << BigInt(subHostBits);
    const aligned = ((current + blockSize - 1n) / blockSize) * blockSize;
    const networkBig = aligned;
    const lastBig = networkBig + blockSize - 1n;

    if (lastBig > baseLastBig) {
      error = `Not enough address space for "${req.name}".`;
      break;
    }

    allocated.push({
      _order: req._order,
      name: req.name,
      network: compressIPv6(bigIntToIPv6Groups(networkBig)),
      prefix: subPrefix,
      firstHost: compressIPv6(bigIntToIPv6Groups(networkBig + 1n)),
      lastHost: compressIPv6(bigIntToIPv6Groups(lastBig)),
      totalAddresses: blockSize.toString(),
    });
    current = lastBig + 1n;
  }
  allocated.sort((a, b) => a._order - b._order);
  return { allocated, error };
}

function Ipv6SubPrefixPlanner({ baseAddr, basePrefix }) {
  const [rows, setRows] = useState([
    { id: 1, name: "Main Office", prefix: 64 },
    { id: 2, name: "Guest Wi-Fi", prefix: 72 },
  ]);

  const updateRow = (id, field, value) => {
    setRows((current) =>
      current.map((row) => (row.id === id ? { ...row, [field]: value } : row)),
    );
  };

  const addRow = () => {
    setRows((current) => [
      ...current,
      { id: Date.now(), name: `Subnet ${current.length + 1}`, prefix: 64 },
    ]);
  };

  const removeRow = (id) => {
    setRows((current) => current.filter((row) => row.id !== id));
  };

  const result = useMemo(() => {
    const normalized = rows.map((row) => ({
      ...row,
      prefix: Number(row.prefix) || Number(basePrefix) + 1,
    }));
    return calcIPv6SubPrefixes(baseAddr, Number(basePrefix), normalized);
  }, [baseAddr, basePrefix, rows]);

  return (
    <div style={{ display: "grid", gap: "12px" }}>
      {rows.map((row) => (
        <div
          key={row.id}
          style={{
            display: "grid",
            gridTemplateColumns: "1.4fr 110px auto",
            gap: "8px",
            alignItems: "end",
          }}
        >
          <Field label="SUBNET NAME">
            <TextInput
              value={row.name}
              onChange={(event) =>
                updateRow(row.id, "name", event.target.value)
              }
            />
          </Field>
          <Field label="PREFIX">
            <TextInput
              value={row.prefix}
              onChange={(event) =>
                updateRow(row.id, "prefix", event.target.value)
              }
              type="number"
              min={Number(basePrefix) + 1}
              max="128"
            />
          </Field>
          <button
            onClick={() => removeRow(row.id)}
            style={{
              padding: "10px 12px",
              borderRadius: "8px",
              border: `1px solid ${C.border}`,
              background: C.panel2,
              color: C.text,
              cursor: "pointer",
            }}
          >
            Remove
          </button>
        </div>
      ))}
      <button
        onClick={addRow}
        style={{
          justifySelf: "start",
          padding: "8px 12px",
          borderRadius: "8px",
          border: `1px solid ${C.border}`,
          background: C.violetSoft,
          color: C.violet,
          cursor: "pointer",
          fontWeight: 600,
        }}
      >
        + Add Sub-Prefix
      </button>
      {result?.error ? (
        <div style={{ color: C.danger, fontSize: "13px" }}>{result.error}</div>
      ) : result?.allocated?.length > 0 ? (
        <div style={S.subPanel}>
          <SectionLabel>ALLOCATED SUB-PREFIXES</SectionLabel>
          {result.allocated.map((item, index) => (
            <div
              key={`${item.name}-${index}`}
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: "12px",
                padding: "8px 0",
                borderTop: index === 0 ? "none" : `1px solid ${C.borderSoft}`,
              }}
            >
              <span style={{ color: C.text, fontWeight: 600 }}>
                {item.name}
              </span>
              <span
                style={{
                  color: C.violet,
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                /{item.prefix}
              </span>
              <span
                style={{
                  color: C.muted,
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                {item.network}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function Ipv6AddressTypePanel({ groups }) {
  const info = detectIPv6AddressType(groups);
  return (
    <div style={S.subPanel}>
      <SectionLabel>ADDRESS TYPE</SectionLabel>
      <StatRow label="Type" value={info.type} accent={info.color} />
      <StatRow label="Scope" value={info.scope} accent={info.color} />
      <StatRow label="Description" value={info.description} accent={C.text} />
      <StatRow label="RFC" value={info.rfc} accent={C.muted} />
    </div>
  );
}

function Ipv6QuickReference() {
  return (
    <div style={S.subPanel}>
      <SectionLabel>QUICK REFERENCE</SectionLabel>
      <div style={{ display: "grid", gap: "8px" }}>
        <div style={{ color: C.text }}>
          <strong>/64</strong> — common LAN or site prefix
        </div>
        <div style={{ color: C.text }}>
          <strong>/126</strong> — point-to-point links
        </div>
        <div style={{ color: C.text }}>
          <strong>/128</strong> — single host address
        </div>
        <div style={{ color: C.muted }}>
          IPv6 subnets are allocated in powers of two, so larger prefixes create
          smaller blocks.
        </div>
      </div>
    </div>
  );
}

/* CIDR reference table */
function buildCidrReference() {
  const rows = [];
  for (let cidr = 8; cidr <= 32; cidr++) {
    const maskInt = cidrToMaskInt(cidr);
    const wildcardInt = ~maskInt >>> 0;
    const total = Math.pow(2, 32 - cidr);
    const usable = cidr === 32 ? 1 : cidr === 31 ? 2 : total - 2;
    rows.push({
      cidr,
      mask: intToIp(maskInt),
      wildcard: intToIp(wildcardInt),
      total,
      usable,
    });
  }
  return rows;
}
const CIDR_REFERENCE = buildCidrReference();

function fmtNum(n) {
  return typeof n === "number" ? n.toLocaleString("en-US") : n;
}
function fmtBigNum(s) {
  try {
    return BigInt(s).toLocaleString("en-US");
  } catch {
    return s;
  }
}

/* Shared styles */
const S = {
  inputBase: {
    background: "#080e16",
    border: "1px solid #1e2a3a",
    color: "#e2e8f4",
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: "14px",
    padding: "10px 12px",
    borderRadius: "8px",
    width: "100%",
    outline: "none",
    boxSizing: "border-box",
  },
  label: {
    display: "block",
    fontSize: "11px",
    fontWeight: 600,
    letterSpacing: "0.07em",
    color: "#6b7d94",
    marginBottom: "6px",
    textTransform: "uppercase",
  },
  panel: {
    background: "#131a24",
    border: "1px solid #1e2a3a",
    borderRadius: "14px",
    padding: "20px 24px",
  },
  subPanel: {
    background: "#0f1720",
    border: "1px solid #19232f",
    borderRadius: "10px",
    padding: "16px",
  },
};

/* Primitives */
function Field({ label, children, style }) {
  return (
    <div style={style}>
      <label style={S.label}>{label}</label>
      {children}
    </div>
  );
}

function TextInput({
  value,
  onChange,
  placeholder,
  type = "text",
  min,
  max,
  style,
}) {
  return (
    <input
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      type={type}
      min={min}
      max={max}
      style={{ ...S.inputBase, ...style }}
    />
  );
}

function StatRow({ label, value, accent, mono = true }) {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "baseline",
        padding: "7px 0",
        gap: "16px",
      }}
    >
      <span
        style={{ fontSize: "12px", color: "#6b7d94", whiteSpace: "nowrap" }}
      >
        {label}
      </span>
      <span
        style={{
          fontSize: "13px",
          fontWeight: 600,
          color: accent || "#e2e8f4",
          textAlign: "right",
          fontFamily: mono ? "'JetBrains Mono', monospace" : "inherit",
          wordBreak: "break-all",
        }}
      >
        {value}
      </span>
    </div>
  );
}

function SectionLabel({ children }) {
  return (
    <div
      style={{
        fontSize: "11px",
        fontWeight: 700,
        letterSpacing: "0.07em",
        color: "#e2e8f4",
        marginBottom: "14px",
      }}
    >
      {children}
    </div>
  );
}

function CidrPill({ children, color }) {
  const c = color || "#1ec2ac";
  return (
    <span
      style={{
        display: "inline-block",
        background: c + "22",
        color: c,
        border: `1px solid ${c}44`,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: "11px",
        fontWeight: 600,
        padding: "2px 7px",
        borderRadius: "5px",
      }}
    >
      {children}
    </span>
  );
}

function Badge({ children, color }) {
  const c = color || C.teal;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        background: c + "20",
        color: c,
        border: `1px solid ${c}40`,
        fontFamily: "'Inter', sans-serif",
        fontSize: "12px",
        fontWeight: 700,
        padding: "4px 12px",
        borderRadius: "20px",
      }}
    >
      {children}
    </span>
  );
}

/* Modal Export */
function ReportExportModal({ title, reportText, onClose }) {
  const [copied, setCopied] = useState(false);

  function copyToClipboard() {
    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function downloadTextFile() {
    const element = document.createElement("a");
    const file = new Blob([reportText], { type: "text/plain" });
    element.href = URL.createObjectURL(file);
    element.download = `${title.toLowerCase().replace(/\s+/g, "_")}_report.txt`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  }

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.75)",
        backdropFilter: "blur(4px)",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        zIndex: 100,
        padding: "16px",
      }}
    >
      <div
        style={{
          background: C.panel,
          border: `1px solid ${C.border}`,
          borderRadius: "14px",
          width: "100%",
          maxWidth: "620px",
          padding: "24px",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span style={{ fontSize: "16px", fontWeight: 700, color: C.text }}>
            📥 {title}
          </span>
          <button
            onClick={onClose}
            style={{
              color: C.muted,
              background: "none",
              border: "none",
              fontSize: "18px",
              cursor: "pointer",
            }}
          >
            ✕
          </button>
        </div>

        <pre
          style={{
            background: "#080e16",
            border: `1px solid ${C.borderSoft}`,
            borderRadius: "8px",
            padding: "14px",
            fontSize: "12px",
            color: C.text,
            fontFamily: "'JetBrains Mono', monospace",
            maxHeight: "340px",
            overflowY: "auto",
            whiteSpace: "pre-wrap",
            margin: 0,
          }}
        >
          {reportText}
        </pre>

        <div
          style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}
        >
          <button
            onClick={copyToClipboard}
            style={{
              padding: "8px 16px",
              borderRadius: "8px",
              background: copied ? C.greenSoft : C.tealSoft,
              color: copied ? C.green : C.teal,
              border: `1px solid ${copied ? C.green : C.teal}40`,
              fontSize: "13px",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            {copied ? "✓ Copied to Clipboard!" : "📋 Copy Text"}
          </button>
          <button
            onClick={downloadTextFile}
            style={{
              padding: "8px 16px",
              borderRadius: "8px",
              background: C.violetSoft,
              color: C.violet,
              border: `1px solid ${C.violet}40`,
              fontSize: "13px",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            💾 Download .txt
          </button>
        </div>
      </div>
    </div>
  );
}

/* Bit breakdown */
function BitBreakdown({ ip, cidr }) {
  const octets = ipBinaryOctets(ip);
  const decParts = ip.trim().split(".");
  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          marginBottom: "14px",
        }}
      >
        <span
          style={{
            fontSize: "11px",
            fontWeight: 700,
            letterSpacing: "0.07em",
            color: "#e2e8f4",
          }}
        >
          BIT-LEVEL BREAKDOWN
        </span>
        <span
          style={{
            display: "flex",
            alignItems: "center",
            gap: "5px",
            fontSize: "11px",
            color: "#6b7d94",
            marginLeft: "4px",
          }}
        >
          <span
            style={{
              width: "10px",
              height: "10px",
              borderRadius: "2px",
              background: "#1ec2ac",
              display: "inline-block",
            }}
          />
          network
          <span
            style={{
              width: "10px",
              height: "10px",
              borderRadius: "2px",
              background: "#f0962a",
              display: "inline-block",
              marginLeft: "8px",
            }}
          />
          host
        </span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "10px" }}>
        {octets.map((oct, oi) => (
          <div
            key={oi}
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: "4px",
            }}
          >
            <div style={{ display: "flex", gap: "2px" }}>
              {oct.split("").map((bit, bi) => {
                const idx = oi * 8 + bi;
                const isNet = idx < cidr;
                const color = isNet ? "#1ec2ac" : "#f0962a";
                const bg = isNet
                  ? "rgba(30,194,172,0.13)"
                  : "rgba(240,150,42,0.13)";
                return (
                  <div
                    key={bi}
                    style={{
                      width: "20px",
                      height: "24px",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      borderRadius: "4px",
                      fontSize: "11px",
                      fontWeight: 700,
                      background: bg,
                      color,
                      border: `1px solid ${color}40`,
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    {bit}
                  </div>
                );
              })}
            </div>
            <span
              style={{
                fontSize: "11px",
                color: "#3d4f63",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              {decParts[oi]}
            </span>
          </div>
        ))}
      </div>
      <div style={{ marginTop: "10px", fontSize: "11px", color: "#3d4f63" }}>
        /{cidr} &mdash; {cidr} network bits, {32 - cidr} host bits
      </div>
    </div>
  );
}

/* Topology Diagram */
function TopologyDiagram({ subnets, title }) {
  const n = subnets.length;
  const width = Math.max(640, n * 185);
  const height = 270;
  const routerX = width / 2;
  const routerY = 50;
  const switchY = 120;
  const cardY = 155;
  const gap = width / (n + 1);
  return (
    <div style={{ overflowX: "auto" }}>
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        style={{ minWidth: width, display: "block" }}
      >
        <text
          x={routerX}
          y={routerY - 26}
          textAnchor="middle"
          fontSize="11"
          fill="#3d4f63"
          fontFamily="'JetBrains Mono', monospace"
        >
          {title}
        </text>
        <rect
          x={routerX - 52}
          y={routerY - 18}
          width="104"
          height="36"
          rx="8"
          fill="#0f1720"
          stroke="#1ec2ac"
          strokeWidth="1.5"
        />
        <text
          x={routerX}
          y={routerY + 7}
          textAnchor="middle"
          fontSize="13"
          fontWeight="700"
          fill="#1ec2ac"
          fontFamily="'JetBrains Mono', monospace"
        >
          ROUTER
        </text>
        {subnets.map((s, i) => {
          const cx = gap * (i + 1);
          const boxW = Math.min(gap - 20, 165);
          const dotCount = Math.min(s.usable, 6);
          const extra = s.usable > 6 ? s.usable - 6 : 0;
          const col = s.color;
          return (
            <g key={i}>
              <path
                d={`M ${routerX} ${routerY + 18} L ${routerX} ${routerY + 36} L ${cx} ${routerY + 36} L ${cx} ${switchY - 12}`}
                fill="none"
                stroke="#19232f"
                strokeWidth="1.5"
              />
              <rect
                x={cx - 32}
                y={switchY - 12}
                width="64"
                height="24"
                rx="5"
                fill="#0a1018"
                stroke={col}
                strokeWidth="1"
              />
              <text
                x={cx}
                y={switchY + 4}
                textAnchor="middle"
                fontSize="10"
                fontWeight="600"
                fill={col}
                fontFamily="'JetBrains Mono', monospace"
              >
                switch
              </text>
              <line
                x1={cx}
                y1={switchY + 12}
                x2={cx}
                y2={cardY}
                stroke="#19232f"
                strokeWidth="1.5"
              />
              <rect
                x={cx - boxW / 2}
                y={cardY}
                width={boxW}
                height="96"
                rx="9"
                fill="#0f1720"
                stroke={col}
                strokeWidth="1.2"
              />
              <text
                x={cx}
                y={cardY + 22}
                textAnchor="middle"
                fontSize="12"
                fontWeight="700"
                fill="#e2e8f4"
                fontFamily="Inter, sans-serif"
              >
                {s.label}
              </text>
              <text
                x={cx}
                y={cardY + 40}
                textAnchor="middle"
                fontSize="10.5"
                fill={col}
                fontFamily="'JetBrains Mono', monospace"
              >
                {s.cidrLabel}
              </text>
              <text
                x={cx}
                y={cardY + 56}
                textAnchor="middle"
                fontSize="9"
                fill="#3d4f63"
                fontFamily="'JetBrains Mono', monospace"
              >
                {s.range}
              </text>
              {Array.from({ length: dotCount }).map((_, di) => {
                const totalW = dotCount * 13;
                const startX = cx - totalW / 2 + 6.5;
                return (
                  <circle
                    key={di}
                    cx={startX + di * 13}
                    cy={cardY + 74}
                    r="4"
                    fill={col}
                    opacity="0.9"
                  />
                );
              })}
              {extra > 0 && (
                <text
                  x={cx}
                  y={cardY + 90}
                  textAnchor="middle"
                  fontSize="9"
                  fill="#3d4f63"
                  fontFamily="'JetBrains Mono', monospace"
                >
                  +{extra} more hosts
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ---------------------------------------------------------
   NEW MODULE 1: Subnetting Quiz & Practice Mode
--------------------------------------------------------- */
function SubnetQuizPanel() {
  const [score, setScore] = useState(0);
  const [streak, setStreak] = useState(0);
  const [userAns, setUserAns] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [isCorrect, setIsCorrect] = useState(false);

  const [problem, setProblem] = useState(generateProblem());

  function generateProblem() {
    const oct1 = [10, 172, 192, 11, 198, 170][Math.floor(Math.random() * 6)];
    const oct2 = Math.floor(Math.random() * 254) + 1;
    const oct3 = Math.floor(Math.random() * 254) + 1;
    const oct4 = Math.floor(Math.random() * 250) + 1;
    const cidr = [16, 24, 25, 26, 27, 28, 29, 30][
      Math.floor(Math.random() * 8)
    ];
    const ip = `${oct1}.${oct2}.${oct3}.${oct4}`;

    const calc = calcIPv4Subnet(ip, cidr);
    const qTypes = [
      {
        id: "network",
        question: `What is the Network Address for ${ip}/${cidr}?`,
        answer: calc.network,
        hint: "Set all host bits to 0.",
      },
      {
        id: "broadcast",
        question: `What is the Broadcast Address for ${ip}/${cidr}?`,
        answer: calc.broadcast,
        hint: "Set all host bits to 1.",
      },
      {
        id: "mask",
        question: `What is the Subnet Mask for /${cidr}?`,
        answer: calc.mask,
        hint: "Convert prefix to dotted-decimal.",
      },
      {
        id: "firstHost",
        question: `What is the First Usable Host IP for ${ip}/${cidr}?`,
        answer: calc.firstHost,
        hint: "Network Address + 1.",
      },
      {
        id: "usable",
        question: `How many Usable Host addresses in a /${cidr} subnet?`,
        answer: calc.usableHosts.toString(),
        hint: "2^(32 - CIDR) - 2.",
      },
    ];
    const target = qTypes[Math.floor(Math.random() * qTypes.length)];
    return { ip, cidr, calc, target };
  }

  function checkAnswer(e) {
    e.preventDefault();
    if (!userAns.trim() || submitted) return;
    const cleanUser = userAns.trim().toLowerCase();
    const cleanTarget = problem.target.answer.trim().toLowerCase();
    const correct = cleanUser === cleanTarget;
    setIsCorrect(correct);
    setSubmitted(true);
    if (correct) {
      setScore((s) => s + 10);
      setStreak((st) => st + 1);
    } else {
      setStreak(0);
    }
  }

  function nextQuestion() {
    setProblem(generateProblem());
    setUserAns("");
    setSubmitted(false);
  }

  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "16px",
        }}
      >
        <SectionLabel>🎯 SUBNETTING PRACTICE CHALLENGE</SectionLabel>
        <div style={{ display: "flex", gap: "12px" }}>
          <Badge color={C.teal}>Score: {score} pts</Badge>
          <Badge color={C.amber}>Streak: {streak} 🔥</Badge>
        </div>
      </div>

      <div style={{ ...S.subPanel, marginBottom: "16px" }}>
        <h3
          style={{
            fontSize: "16px",
            fontWeight: 700,
            color: C.text,
            margin: "0 0 8px",
          }}
        >
          {problem.target.question}
        </h3>
        <p style={{ fontSize: "12px", color: C.muted, margin: "0 0 16px" }}>
          Target IP:{" "}
          <span
            style={{ color: C.teal, fontFamily: "'JetBrains Mono', monospace" }}
          >
            {problem.ip}/{problem.cidr}
          </span>
        </p>

        <form onSubmit={checkAnswer} style={{ display: "flex", gap: "10px" }}>
          <TextInput
            value={userAns}
            onChange={(e) => setUserAns(e.target.value)}
            placeholder="Type your answer here..."
            disabled={submitted}
            style={{ flex: 1 }}
          />
          {!submitted ? (
            <button
              type="submit"
              style={{
                padding: "10px 20px",
                borderRadius: "8px",
                background: C.teal,
                color: "#0a0e14",
                fontWeight: 700,
                fontSize: "13px",
                border: "none",
                cursor: "pointer",
              }}
            >
              Submit Answer
            </button>
          ) : (
            <button
              type="button"
              onClick={nextQuestion}
              style={{
                padding: "10px 20px",
                borderRadius: "8px",
                background: C.violet,
                color: "#fff",
                fontWeight: 700,
                fontSize: "13px",
                border: "none",
                cursor: "pointer",
              }}
            >
              Next Problem ▶
            </button>
          )}
        </form>

        {submitted && (
          <div
            style={{
              marginTop: "16px",
              padding: "14px",
              borderRadius: "8px",
              background: isCorrect ? C.greenSoft : C.dangerSoft,
              border: `1px solid ${isCorrect ? C.green : C.danger}40`,
            }}
          >
            <div
              style={{
                fontSize: "14px",
                fontWeight: 700,
                color: isCorrect ? C.green : C.danger,
                marginBottom: "6px",
              }}
            >
              {isCorrect ? "🎉 Correct! Great job." : `❌ Incorrect.`}
            </div>
            {!isCorrect && (
              <div style={{ fontSize: "12px", color: C.text }}>
                Correct Answer:{" "}
                <span
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    color: C.teal,
                    fontWeight: 700,
                  }}
                >
                  {problem.target.answer}
                </span>
                <br />
                <span style={{ color: C.muted }}>
                  Hint / Method: {problem.target.hint}
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------
   NEW MODULE 2: DNS Resolution Visualizer
--------------------------------------------------------- */
function DnsVisualizerPanel() {
  const [step, setStep] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);

  const steps = [
    {
      title: "Step 0: User types 'www.example.com'",
      node: "Client",
      desc: "Browser checks local OS DNS cache. Cache miss! Request sent to configured Recursive Resolver (e.g. 8.8.8.8).",
      activeNode: "client",
      color: C.muted,
    },
    {
      title: "Step 1: Query sent to Local Recursive Resolver",
      node: "Resolver (8.8.8.8)",
      desc: "Recursive resolver checks its cache. Cache miss! Resolver starts iterative query flow to find authoritative IP.",
      activeNode: "resolver",
      color: C.teal,
    },
    {
      title: "Step 2: Resolver queries Root Nameserver (.)",
      node: "Root Server (.)",
      desc: "Root server doesn't know 'example.com', but refers the Resolver to the .COM TLD Nameserver.",
      activeNode: "root",
      color: C.blue,
    },
    {
      title: "Step 3: Resolver queries TLD Nameserver (.com)",
      node: "TLD Server (.com)",
      desc: ".COM TLD server refers Resolver to Authoritative Nameserver for 'example.com' (ns1.example.com).",
      activeNode: "tld",
      color: C.violet,
    },
    {
      title: "Step 4: Resolver queries Authoritative Nameserver",
      node: "Auth Server (ns1.example.com)",
      desc: "Authoritative server looks up A Record and returns IP: 93.184.216.34 (TTL=3600).",
      activeNode: "auth",
      color: C.pink,
    },
    {
      title: "Step 5: Resolver Caches & Returns IP to Client",
      node: "Client Connection",
      desc: "Resolver caches IP 93.184.216.34 and returns it to Client. Client initiates TCP/HTTPS connection on port 443!",
      activeNode: "done",
      color: C.green,
    },
  ];

  useEffect(() => {
    let timer;
    if (isPlaying) {
      timer = setInterval(() => {
        setStep((s) => (s < steps.length - 1 ? s + 1 : 0));
      }, 2500);
    }
    return () => clearInterval(timer);
  }, [isPlaying, steps.length]);

  const currentStep = steps[step];

  return (
    <div>
      <SectionLabel>🌐 INTERACTIVE DNS RESOLUTION SIMULATOR</SectionLabel>

      <div style={{ ...S.subPanel, marginBottom: "12px", textAlign: "center" }}>
        {/* Controls */}
        <div
          style={{
            display: "flex",
            justifyContent: "center",
            gap: "10px",
            marginBottom: "16px",
          }}
        >
          <button
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            style={{
              padding: "6px 14px",
              borderRadius: "6px",
              background: C.panel,
              color: C.text,
              border: `1px solid ${C.border}`,
              fontSize: "12px",
              cursor: "pointer",
            }}
          >
            ◀ Prev
          </button>
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            style={{
              padding: "6px 16px",
              borderRadius: "6px",
              background: isPlaying ? C.amberSoft : C.tealSoft,
              color: isPlaying ? C.amber : C.teal,
              border: `1px solid ${isPlaying ? C.amber : C.teal}40`,
              fontSize: "12px",
              fontWeight: 700,
              cursor: "pointer",
            }}
          >
            {isPlaying ? "⏸ Pause" : "▶ Auto Play"}
          </button>
          <button
            onClick={() => setStep((s) => Math.min(steps.length - 1, s + 1))}
            style={{
              padding: "6px 14px",
              borderRadius: "6px",
              background: C.panel,
              color: C.text,
              border: `1px solid ${C.border}`,
              fontSize: "12px",
              cursor: "pointer",
            }}
          >
            Next ▶
          </button>
          <button
            onClick={() => {
              setStep(0);
              setIsPlaying(false);
            }}
            style={{
              padding: "6px 12px",
              borderRadius: "6px",
              background: C.panel,
              color: C.muted,
              border: `1px solid ${C.border}`,
              fontSize: "12px",
              cursor: "pointer",
            }}
          >
            🔄 Reset
          </button>
        </div>

        {/* Graph SVG */}
        <svg
          width="100%"
          height="180"
          viewBox="0 0 650 180"
          style={{ maxWidth: "650px", margin: "0 auto", display: "block" }}
        >
          {/* Client */}
          <rect
            x="20"
            y="70"
            width="90"
            height="45"
            rx="8"
            fill={C.panel2}
            stroke={
              currentStep.activeNode === "client" ||
              currentStep.activeNode === "done"
                ? C.teal
                : C.border
            }
            strokeWidth="1.5"
          />
          <text
            x="65"
            y="97"
            textAnchor="middle"
            fill={C.text}
            fontSize="11"
            fontWeight="700"
          >
            Client
          </text>

          {/* Local Resolver */}
          <rect
            x="150"
            y="70"
            width="110"
            height="45"
            rx="8"
            fill={C.panel2}
            stroke={currentStep.activeNode === "resolver" ? C.teal : C.border}
            strokeWidth="1.5"
          />
          <text
            x="205"
            y="97"
            textAnchor="middle"
            fill={C.text}
            fontSize="11"
            fontWeight="700"
          >
            DNS Resolver
          </text>

          {/* Root */}
          <rect
            x="300"
            y="20"
            width="100"
            height="40"
            rx="8"
            fill={C.panel2}
            stroke={currentStep.activeNode === "root" ? C.blue : C.border}
            strokeWidth="1.5"
          />
          <text
            x="350"
            y="44"
            textAnchor="middle"
            fill={C.blue}
            fontSize="11"
            fontWeight="700"
          >
            Root (.)
          </text>

          {/* TLD */}
          <rect
            x="440"
            y="70"
            width="100"
            height="40"
            rx="8"
            fill={C.panel2}
            stroke={currentStep.activeNode === "tld" ? C.violet : C.border}
            strokeWidth="1.5"
          />
          <text
            x="490"
            y="94"
            textAnchor="middle"
            fill={C.violet}
            fontSize="11"
            fontWeight="700"
          >
            TLD (.com)
          </text>

          {/* Auth */}
          <rect
            x="520"
            y="130"
            width="110"
            height="40"
            rx="8"
            fill={C.panel2}
            stroke={currentStep.activeNode === "auth" ? C.pink : C.border}
            strokeWidth="1.5"
          />
          <text
            x="575"
            y="154"
            textAnchor="middle"
            fill={C.pink}
            fontSize="11"
            fontWeight="700"
          >
            Auth Server
          </text>

          {/* Arrows */}
          <line
            x1="110"
            y1="92"
            x2="150"
            y2="92"
            stroke={C.borderSoft}
            strokeWidth="2"
          />
          <line
            x1="260"
            y1="80"
            x2="300"
            y2="40"
            stroke={C.borderSoft}
            strokeWidth="2"
          />
          <line
            x1="260"
            y1="92"
            x2="440"
            y2="90"
            stroke={C.borderSoft}
            strokeWidth="2"
          />
          <line
            x1="260"
            y1="105"
            x2="520"
            y2="145"
            stroke={C.borderSoft}
            strokeWidth="2"
          />
        </svg>
      </div>

      <div
        style={{ ...S.subPanel, borderLeft: `3px solid ${currentStep.color}` }}
      >
        <div
          style={{
            fontSize: "14px",
            fontWeight: 700,
            color: currentStep.color,
            marginBottom: "6px",
          }}
        >
          {currentStep.title}
        </div>
        <p style={{ fontSize: "13px", color: C.text, margin: 0 }}>
          {currentStep.desc}
        </p>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------
   NEW MODULE 3 & 4: Security & Hardware Encyclopedia
--------------------------------------------------------- */
function SecurityAndDevicesPanel() {
  const [subTab, setSubTab] = useState("security");

  const securityTopics = [
    {
      name: "Firewall Protection",
      tag: "Packet / Stateful / NGFW",
      color: C.teal,
      desc: "Monitors and filters incoming/outgoing network traffic based on security rules. NGFW inspects up to Layer 7 application data.",
    },
    {
      name: "VPN (Virtual Private Network)",
      tag: "IPsec / OpenVPN / WireGuard",
      color: C.blue,
      desc: "Encrypts tunnel traffic over untrusted networks (the Internet) connecting remote users/sites securely.",
    },
    {
      name: "NAT & PAT",
      tag: "Network & Port Address Translation",
      color: C.amber,
      desc: "Translates private RFC 1918 IPs to public IPv4 addresses, conserving public IP space and hiding internal networks.",
    },
    {
      name: "IDS vs IPS",
      tag: "Intrusion Detection vs Prevention",
      color: C.pink,
      desc: "IDS passively monitors and alerts on suspicious traffic. IPS actively blocks malicious packets inline.",
    },
    {
      name: "ARP Spoofing & Mitigation",
      tag: "Man-In-The-Middle Prevention",
      color: C.danger,
      desc: "Attackers send fake ARP messages to tie their MAC to a target IP. Mitigated with Dynamic ARP Inspection (DAI).",
    },
    {
      name: "SSL/TLS & HTTPS Encryption",
      tag: "Public Key Infrastructure (PKI)",
      color: C.violet,
      desc: "Secures web traffic using asymmetric RSA/ECC certificates and symmetric AES session encryption.",
    },
  ];

  const devicesData = [
    {
      name: "Router",
      layer: "Layer 3 (Network)",
      color: C.teal,
      desc: "Forwards packets between different IP subnets/networks using routing tables (OSPF, BGP).",
    },
    {
      name: "Layer 2 Switch",
      layer: "Layer 2 (Data Link)",
      color: C.blue,
      desc: "Connects devices in a LAN segment, forwarding frames based on MAC address tables.",
    },
    {
      name: "Layer 3 Switch",
      layer: "Layer 2 & Layer 3",
      color: C.violet,
      desc: "Combines fast hardware frame switching with IP routing between VLANs.",
    },
    {
      name: "Next-Gen Firewall (NGFW)",
      layer: "Layers 3 to 7",
      color: C.pink,
      desc: "Deep packet inspection, application recognition, and threat prevention.",
    },
    {
      name: "Wireless Access Point (AP)",
      layer: "Layer 1 & Layer 2",
      color: C.amber,
      desc: "Bridges wireless Wi-Fi clients (802.11) to a wired Ethernet network.",
    },
    {
      name: "Ethernet Hub (Legacy)",
      layer: "Layer 1 (Physical)",
      color: C.faint,
      desc: "Repeats received bits to all connected ports (Single collision domain, obsolete).",
    },
  ];

  return (
    <div>
      <div
        style={{
          display: "flex",
          gap: "12px",
          borderBottom: `1px solid ${C.border}`,
          marginBottom: "16px",
        }}
      >
        {[
          { id: "security", label: "🛡️ Network Security Overview" },
          { id: "devices", label: "📟 Network Device Encyclopedia" },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setSubTab(t.id)}
            style={{
              padding: "8px 12px",
              background: "none",
              border: "none",
              cursor: "pointer",
              fontSize: "13px",
              fontWeight: 600,
              color: subTab === t.id ? C.teal : C.muted,
              borderBottom:
                subTab === t.id
                  ? `2px solid ${C.teal}`
                  : "2px solid transparent",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {subTab === "security" && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
            gap: "12px",
          }}
        >
          {securityTopics.map((item) => (
            <div
              key={item.name}
              style={{
                background: C.panel2,
                border: `1px solid ${item.color}35`,
                borderRadius: "10px",
                padding: "14px",
                borderLeft: `4px solid ${item.color}`,
              }}
            >
              <div
                style={{
                  fontSize: "14px",
                  fontWeight: 700,
                  color: item.color,
                  marginBottom: "4px",
                }}
              >
                {item.name}
              </div>
              <div
                style={{
                  fontSize: "10px",
                  color: C.muted,
                  fontFamily: "'JetBrains Mono', monospace",
                  marginBottom: "8px",
                }}
              >
                {item.tag}
              </div>
              <div
                style={{ fontSize: "12px", color: C.text, lineHeight: "1.5" }}
              >
                {item.desc}
              </div>
            </div>
          ))}
        </div>
      )}

      {subTab === "devices" && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
            gap: "12px",
          }}
        >
          {devicesData.map((item) => (
            <div
              key={item.name}
              style={{
                background: C.panel2,
                border: `1px solid ${item.color}35`,
                borderRadius: "10px",
                padding: "14px",
                borderLeft: `4px solid ${item.color}`,
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "baseline",
                  marginBottom: "4px",
                }}
              >
                <span
                  style={{
                    fontSize: "14px",
                    fontWeight: 700,
                    color: item.color,
                  }}
                >
                  {item.name}
                </span>
              </div>
              <CidrPill color={item.color}>{item.layer}</CidrPill>
              <div
                style={{
                  fontSize: "12px",
                  color: C.text,
                  marginTop: "8px",
                  lineHeight: "1.5",
                }}
              >
                {item.desc}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------------------------------------------------------
   NEW MODULE 5: IPv4 vs IPv6 Comparison Matrix
--------------------------------------------------------- */
function Ipv4VsIpv6Matrix() {
  const matrix = [
    {
      feature: "Address Length",
      v4: "32 bits (4 Bytes)",
      v6: "128 bits (16 Bytes)",
    },
    {
      feature: "Address Format",
      v4: "Dotted Decimal (e.g. 192.168.1.1)",
      v6: "Hexadecimal Hextets (e.g. 2001:db8::1)",
    },
    {
      feature: "Total Addresses",
      v4: "2^32 ≈ 4.29 Billion",
      v6: "2^128 ≈ 3.4 × 10^38 (340 Undecillion)",
    },
    {
      feature: "Header Size",
      v4: "Variable (20 to 60 Bytes)",
      v6: "Fixed (40 Bytes)",
    },
    {
      feature: "Addressing Modes",
      v4: "Unicast, Broadcast, Multicast",
      v6: "Unicast, Multicast, Anycast (No Broadcast!)",
    },
    {
      feature: "Host Auto-Config",
      v4: "DHCP or Manual",
      v6: "SLAAC (Stateless) or DHCPv6",
    },
    {
      feature: "IP Security (IPSec)",
      v4: "Optional add-on",
      v6: "Natively built into protocol",
    },
    {
      feature: "NAT Dependency",
      v4: "Required (RFC 1918 private space)",
      v6: "Not required (Abundant global addresses)",
    },
    {
      feature: "Packet Fragmentation",
      v4: "Performed by Routers & Sender",
      v6: "Performed ONLY by Sender",
    },
  ];

  return (
    <div>
      <SectionLabel>
        ⚡ SIDE-BY-SIDE PROTOCOL COMPARISON (IPv4 vs IPv6)
      </SectionLabel>

      <div
        style={{
          borderRadius: "10px",
          overflow: "hidden",
          border: `1px solid ${C.borderSoft}`,
        }}
      >
        <table
          style={{
            width: "100%",
            fontSize: "13px",
            borderCollapse: "collapse",
          }}
        >
          <thead>
            <tr style={{ background: C.panel2 }}>
              {["Feature / Characteristic", "IPv4", "IPv6"].map((h) => (
                <th
                  key={h}
                  style={{
                    textAlign: "left",
                    fontSize: "11px",
                    color: C.muted,
                    padding: "10px 14px",
                    borderBottom: `1px solid ${C.borderSoft}`,
                  }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.map((m, idx) => (
              <tr
                key={m.feature}
                style={{
                  background:
                    idx % 2 === 0 ? "transparent" : "rgba(255,255,255,0.015)",
                  borderBottom: `1px solid ${C.borderSoft}`,
                }}
              >
                <td
                  style={{
                    padding: "10px 14px",
                    fontWeight: 700,
                    color: C.text,
                  }}
                >
                  {m.feature}
                </td>
                <td
                  style={{
                    padding: "10px 14px",
                    color: C.teal,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {m.v4}
                </td>
                <td
                  style={{
                    padding: "10px 14px",
                    color: C.violet,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {m.v6}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------
   TCP 3-Way Handshake & Packet Encapsulation Component
--------------------------------------------------------- */
function TcpVisualizerPanel() {
  const [subTab, setSubTab] = useState("handshake");
  const [step, setStep] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);

  const steps = [
    {
      title: "Step 0: Connection Closed",
      sender: "Client",
      receiver: "Server",
      flag: "NONE",
      seq: "-",
      ack: "-",
      win: "-",
      clientState: "CLOSED",
      serverState: "LISTEN",
      desc: "Server is in LISTEN state on port 80, waiting for incoming TCP connection requests.",
      color: C.muted,
    },
    {
      title: "Step 1: SYN (Synchronize)",
      sender: "Client (192.168.1.50:49152)",
      receiver: "Server (93.184.216.34:80)",
      flag: "SYN",
      seq: "1000",
      ack: "0",
      win: "64240",
      clientState: "SYN_SENT",
      serverState: "LISTEN",
      desc: "Client picks an Initial Sequence Number (ISN=1000) and sends a SYN packet to initiate a connection.",
      color: C.teal,
    },
    {
      title: "Step 2: SYN-ACK (Synchronize-Acknowledge)",
      sender: "Server (93.184.216.34:80)",
      receiver: "Client (192.168.1.50:49152)",
      flag: "SYN, ACK",
      seq: "5000",
      ack: "1001",
      win: "65535",
      clientState: "SYN_SENT",
      serverState: "SYN_RCVD",
      desc: "Server acknowledges client's ISN (ACK=1001) and sends its own ISN (SEQ=5000) in a SYN-ACK packet.",
      color: C.amber,
    },
    {
      title: "Step 3: ACK (Acknowledge)",
      sender: "Client (192.168.1.50:49152)",
      receiver: "Server (93.184.216.34:80)",
      flag: "ACK",
      seq: "1001",
      ack: "5001",
      win: "64240",
      clientState: "ESTABLISHED",
      serverState: "SYN_RCVD",
      desc: "Client acknowledges server's ISN (ACK=5001). Handshake complete!",
      color: C.violet,
    },
    {
      title: "Step 4: Connection Established",
      sender: "Client & Server",
      receiver: "Full Duplex Data Flow",
      flag: "ESTABLISHED",
      seq: "Data",
      ack: "Data",
      win: "Active",
      clientState: "ESTABLISHED",
      serverState: "ESTABLISHED",
      desc: "Both endpoints are in ESTABLISHED state. Reliable full-duplex data transmission begins.",
      color: C.green,
    },
  ];

  useEffect(() => {
    let timer;
    if (isPlaying) {
      timer = setInterval(() => {
        setStep((s) => (s < steps.length - 1 ? s + 1 : 0));
      }, 2500);
    }
    return () => clearInterval(timer);
  }, [isPlaying, steps.length]);

  const currentStep = steps[step];

  return (
    <div>
      <div
        style={{
          display: "flex",
          gap: "12px",
          borderBottom: `1px solid ${C.border}`,
          marginBottom: "16px",
        }}
      >
        {[
          { id: "handshake", label: "🤝 TCP 3-Way Handshake Animation" },
          { id: "encapsulation", label: "📦 Packet Flow Encapsulation" },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setSubTab(t.id)}
            style={{
              padding: "8px 12px",
              background: "none",
              border: "none",
              cursor: "pointer",
              fontSize: "13px",
              fontWeight: 600,
              color: subTab === t.id ? C.teal : C.muted,
              borderBottom:
                subTab === t.id
                  ? `2px solid ${C.teal}`
                  : "2px solid transparent",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {subTab === "handshake" && (
        <div>
          <div
            style={{ ...S.subPanel, marginBottom: "12px", textAlign: "center" }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "center",
                gap: "10px",
                marginBottom: "16px",
              }}
            >
              <button
                onClick={() => setStep((s) => Math.max(0, s - 1))}
                style={{
                  padding: "6px 14px",
                  borderRadius: "6px",
                  background: C.panel,
                  color: C.text,
                  border: `1px solid ${C.border}`,
                  fontSize: "12px",
                  cursor: "pointer",
                }}
              >
                ◀ Prev
              </button>
              <button
                onClick={() => setIsPlaying(!isPlaying)}
                style={{
                  padding: "6px 16px",
                  borderRadius: "6px",
                  background: isPlaying ? C.amberSoft : C.tealSoft,
                  color: isPlaying ? C.amber : C.teal,
                  border: `1px solid ${isPlaying ? C.amber : C.teal}40`,
                  fontSize: "12px",
                  fontWeight: 700,
                  cursor: "pointer",
                }}
              >
                {isPlaying ? "⏸ Pause" : "▶ Auto Play"}
              </button>
              <button
                onClick={() =>
                  setStep((s) => Math.min(steps.length - 1, s + 1))
                }
                style={{
                  padding: "6px 14px",
                  borderRadius: "6px",
                  background: C.panel,
                  color: C.text,
                  border: `1px solid ${C.border}`,
                  fontSize: "12px",
                  cursor: "pointer",
                }}
              >
                Next ▶
              </button>
              <button
                onClick={() => {
                  setStep(0);
                  setIsPlaying(false);
                }}
                style={{
                  padding: "6px 12px",
                  borderRadius: "6px",
                  background: C.panel,
                  color: C.muted,
                  border: `1px solid ${C.border}`,
                  fontSize: "12px",
                  cursor: "pointer",
                }}
              >
                🔄 Reset
              </button>
            </div>

            <svg
              width="100%"
              height="160"
              viewBox="0 0 600 160"
              style={{ maxWidth: "600px", margin: "0 auto", display: "block" }}
            >
              <rect
                x="30"
                y="30"
                width="120"
                height="70"
                rx="10"
                fill={C.panel2}
                stroke={C.teal}
                strokeWidth="1.5"
              />
              <text
                x="90"
                y="55"
                textAnchor="middle"
                fill={C.text}
                fontSize="13"
                fontWeight="700"
              >
                CLIENT
              </text>
              <text
                x="90"
                y="74"
                textAnchor="middle"
                fill={C.teal}
                fontSize="10"
                fontFamily="'JetBrains Mono', monospace"
              >
                {currentStep.clientState}
              </text>

              <rect
                x="450"
                y="30"
                width="120"
                height="70"
                rx="10"
                fill={C.panel2}
                stroke={C.violet}
                strokeWidth="1.5"
              />
              <text
                x="510"
                y="55"
                textAnchor="middle"
                fill={C.text}
                fontSize="13"
                fontWeight="700"
              >
                SERVER
              </text>
              <text
                x="510"
                y="74"
                textAnchor="middle"
                fill={C.violet}
                fontSize="10"
                fontFamily="'JetBrains Mono', monospace"
              >
                {currentStep.serverState}
              </text>

              <line
                x1="150"
                y1="65"
                x2="450"
                y2="65"
                stroke={C.borderSoft}
                strokeWidth="2"
                strokeDasharray="4"
              />

              {step > 0 && step < 4 && (
                <g>
                  <line
                    x1={step === 2 ? 430 : 170}
                    y1="65"
                    x2={step === 2 ? 170 : 430}
                    y2="65"
                    stroke={currentStep.color}
                    strokeWidth="3"
                  />
                  <rect
                    x="240"
                    y="45"
                    width="120"
                    height="40"
                    rx="6"
                    fill={C.panel}
                    stroke={currentStep.color}
                    strokeWidth="1.5"
                  />
                  <text
                    x="300"
                    y="62"
                    textAnchor="middle"
                    fill={currentStep.color}
                    fontSize="11"
                    fontWeight="700"
                  >
                    {currentStep.flag}
                  </text>
                  <text
                    x="300"
                    y="77"
                    textAnchor="middle"
                    fill={C.muted}
                    fontSize="9"
                    fontFamily="'JetBrains Mono', monospace"
                  >
                    SEQ={currentStep.seq} ACK={currentStep.ack}
                  </text>
                </g>
              )}

              {step === 4 && (
                <text
                  x="300"
                  y="70"
                  textAnchor="middle"
                  fill={C.green}
                  fontSize="13"
                  fontWeight="700"
                >
                  ⚡ ESTABLISHED (Data Flow Active)
                </text>
              )}
            </svg>
          </div>

          <div
            style={{
              ...S.subPanel,
              borderLeft: `3px solid ${currentStep.color}`,
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "baseline",
                marginBottom: "8px",
              }}
            >
              <span
                style={{
                  fontSize: "14px",
                  fontWeight: 700,
                  color: currentStep.color,
                }}
              >
                {currentStep.title}
              </span>
              <Badge color={currentStep.color}>{currentStep.flag}</Badge>
            </div>
            <p style={{ fontSize: "13px", color: C.text, margin: "0 0 12px" }}>
              {currentStep.desc}
            </p>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(4, 1fr)",
                gap: "8px",
                background: "#080e16",
                padding: "10px",
                borderRadius: "6px",
              }}
            >
              <div>
                <span style={{ fontSize: "10px", color: C.muted }}>FLAGS</span>
                <br />
                <span
                  style={{
                    fontSize: "12px",
                    color: C.text,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {currentStep.flag}
                </span>
              </div>
              <div>
                <span style={{ fontSize: "10px", color: C.muted }}>
                  SEQ NUM
                </span>
                <br />
                <span
                  style={{
                    fontSize: "12px",
                    color: C.teal,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {currentStep.seq}
                </span>
              </div>
              <div>
                <span style={{ fontSize: "10px", color: C.muted }}>
                  ACK NUM
                </span>
                <br />
                <span
                  style={{
                    fontSize: "12px",
                    color: C.amber,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {currentStep.ack}
                </span>
              </div>
              <div>
                <span style={{ fontSize: "10px", color: C.muted }}>
                  WIN SIZE
                </span>
                <br />
                <span
                  style={{
                    fontSize: "12px",
                    color: C.text,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {currentStep.win}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {subTab === "encapsulation" && (
        <div style={S.subPanel}>
          <SectionLabel>PROTOCOL STACK ENCAPSULATION</SectionLabel>
          <div
            style={{ display: "flex", flexDirection: "column", gap: "10px" }}
          >
            {[
              {
                layer: "7. Application",
                name: "HTTP Data Payload",
                color: C.teal,
                content: "GET /index.html HTTP/1.1",
              },
              {
                layer: "4. Transport",
                name: "TCP Segment",
                color: C.blue,
                content:
                  "[TCP Header: SrcPort=49152, DstPort=80, SEQ=1001] + Payload",
              },
              {
                layer: "3. Network",
                name: "IP Packet",
                color: C.violet,
                content:
                  "[IP Header: SrcIP=192.168.1.50, DstIP=93.184.216.34] + TCP Segment",
              },
              {
                layer: "2. Data Link",
                name: "Ethernet Frame",
                color: C.pink,
                content:
                  "[Eth Header: SrcMAC=aa:bb:cc:11, DstMAC=dd:ee:ff:22] + IP Packet + [FCS]",
              },
              {
                layer: "1. Physical",
                name: "Bits (Physical)",
                color: C.amber,
                content: "01000111 01000101 01010100 00100000 00101111 ...",
              },
            ].map((item, idx) => (
              <div
                key={idx}
                style={{
                  background: "#080e16",
                  border: `1px solid ${item.color}35`,
                  borderRadius: "8px",
                  padding: "12px 14px",
                  borderLeft: `4px solid ${item.color}`,
                }}
              >
                <span
                  style={{
                    fontSize: "11px",
                    fontWeight: 700,
                    color: item.color,
                  }}
                >
                  {item.layer} &mdash; {item.name}
                </span>
                <div
                  style={{
                    fontSize: "12px",
                    color: C.text,
                    fontFamily: "'JetBrains Mono', monospace",
                    marginTop: "4px",
                  }}
                >
                  {item.content}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------------------------------------------------
   OSI 7-Layer Model & Port Directory Component
--------------------------------------------------------- */
function OsiAndPortsPanel() {
  const [tab, setTab] = useState("osi");
  const [selectedLayer, setSelectedLayer] = useState(7);
  const [portSearch, setPortSearch] = useState("");

  const osiLayers = [
    {
      num: 7,
      name: "Application",
      pdu: "Data",
      color: "#e07bc2",
      protocols: "HTTP, HTTPS, DNS, FTP, SSH, SMTP, DHCP",
      devices: "Firewall (Layer 7), Gateway",
      desc: "Provides network services directly to user applications.",
    },
    {
      num: 6,
      name: "Presentation",
      pdu: "Data",
      color: "#8b72e8",
      protocols: "SSL/TLS, JPEG, PNG, ASCII, MPEG",
      devices: "Software Encryption Engines",
      desc: "Formats, encrypts, and compresses data.",
    },
    {
      num: 5,
      name: "Session",
      pdu: "Data",
      color: "#5fa8f5",
      protocols: "NetBIOS, PPTP, RPC, SOCKS",
      devices: "Application Gateways",
      desc: "Establishes, manages, and terminates session connections.",
    },
    {
      num: 4,
      name: "Transport",
      pdu: "Segment / Datagram",
      color: "#1ec2ac",
      protocols: "TCP, UDP, SCTP",
      devices: "Load Balancer, Layer 4 Firewall",
      desc: "Ensures end-to-end reliable data delivery and port multiplexing.",
    },
    {
      num: 3,
      name: "Network",
      pdu: "Packet",
      color: "#7dce6a",
      protocols: "IPv4, IPv6, ICMP, ARP, OSPF, BGP",
      devices: "Router, Layer 3 Switch",
      desc: "Handles logical IP addressing and routing.",
    },
    {
      num: 2,
      name: "Data Link",
      pdu: "Frame",
      color: "#f0962a",
      protocols: "Ethernet (802.3), Wi-Fi (802.11), VLAN",
      devices: "Network Switch, Bridge, NIC",
      desc: "Manages MAC addressing and frame delivery.",
    },
    {
      num: 1,
      name: "Physical",
      pdu: "Bits",
      color: "#e05470",
      protocols: "100BASE-T, Optical Fiber, Bluetooth",
      devices: "Hub, Repeater, Fiber Cable, Modem",
      desc: "Transmits raw bitstreams over physical media.",
    },
  ];

  const portsData = [
    {
      port: 20,
      proto: "TCP",
      service: "FTP Data",
      cat: "File",
      desc: "FTP data channel.",
    },
    {
      port: 21,
      proto: "TCP",
      service: "FTP Control",
      cat: "File",
      desc: "FTP command channel.",
    },
    {
      port: 22,
      proto: "TCP",
      service: "SSH / SFTP",
      cat: "Remote",
      desc: "Secure Shell remote access.",
    },
    {
      port: 23,
      proto: "TCP",
      service: "Telnet",
      cat: "Remote",
      desc: "Unencrypted remote terminal.",
    },
    {
      port: 25,
      proto: "TCP",
      service: "SMTP",
      cat: "Mail",
      desc: "Simple Mail Transfer Protocol.",
    },
    {
      port: 53,
      proto: "TCP/UDP",
      service: "DNS",
      cat: "Web/DNS",
      desc: "Domain Name System resolution.",
    },
    {
      port: 80,
      proto: "TCP",
      service: "HTTP",
      cat: "Web/DNS",
      desc: "Hypertext Transfer Protocol.",
    },
    {
      port: 110,
      proto: "TCP",
      service: "POP3",
      cat: "Mail",
      desc: "Post Office Protocol v3.",
    },
    {
      port: 123,
      proto: "UDP",
      service: "NTP",
      cat: "System",
      desc: "Network Time Protocol.",
    },
    {
      port: 143,
      proto: "TCP",
      service: "IMAP",
      cat: "Mail",
      desc: "Internet Message Access Protocol.",
    },
    {
      port: 443,
      proto: "TCP",
      service: "HTTPS",
      cat: "Web/DNS",
      desc: "HTTP over TLS/SSL encryption.",
    },
    {
      port: 445,
      proto: "TCP",
      service: "SMB",
      cat: "File",
      desc: "Windows file sharing.",
    },
    {
      port: 3306,
      proto: "TCP",
      service: "MySQL",
      cat: "Database",
      desc: "MySQL database port.",
    },
    {
      port: 3389,
      proto: "TCP",
      service: "RDP",
      cat: "Remote",
      desc: "Remote Desktop Protocol.",
    },
    {
      port: 5432,
      proto: "TCP",
      service: "PostgreSQL",
      cat: "Database",
      desc: "PostgreSQL database port.",
    },
    {
      port: 8080,
      proto: "TCP",
      service: "HTTP Alt",
      cat: "Web/DNS",
      desc: "Web app proxy & dev port.",
    },
  ];

  const activeOsiLayer =
    osiLayers.find((l) => l.num === selectedLayer) || osiLayers[0];
  const filteredPorts = portsData.filter(
    (p) =>
      p.service.toLowerCase().includes(portSearch.toLowerCase()) ||
      p.port.toString().includes(portSearch) ||
      p.proto.toLowerCase().includes(portSearch.toLowerCase()),
  );

  return (
    <div>
      <div
        style={{
          display: "flex",
          gap: "12px",
          borderBottom: `1px solid ${C.border}`,
          marginBottom: "16px",
        }}
      >
        {[
          { id: "osi", label: "🏗️ OSI 7-Layer Model Explorer" },
          { id: "ports", label: "🔌 Port Directory Reference" },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              padding: "8px 12px",
              background: "none",
              border: "none",
              cursor: "pointer",
              fontSize: "13px",
              fontWeight: 600,
              color: tab === t.id ? C.teal : C.muted,
              borderBottom:
                tab === t.id ? `2px solid ${C.teal}` : "2px solid transparent",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "osi" && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "240px 1fr",
            gap: "16px",
          }}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {osiLayers.map((l) => (
              <button
                key={l.num}
                onClick={() => setSelectedLayer(l.num)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "10px 12px",
                  borderRadius: "8px",
                  border: `1px solid ${selectedLayer === l.num ? l.color : C.border}`,
                  background:
                    selectedLayer === l.num ? `${l.color}18` : C.panel2,
                  color: selectedLayer === l.num ? l.color : C.text,
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
                <span style={{ fontSize: "12px", fontWeight: 700 }}>
                  Layer {l.num}: {l.name}
                </span>
              </button>
            ))}
          </div>

          <div
            style={{
              ...S.subPanel,
              borderLeft: `4px solid ${activeOsiLayer.color}`,
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "10px",
              }}
            >
              <span
                style={{
                  fontSize: "16px",
                  fontWeight: 800,
                  color: activeOsiLayer.color,
                }}
              >
                Layer {activeOsiLayer.num}: {activeOsiLayer.name}
              </span>
              <CidrPill color={activeOsiLayer.color}>
                PDU: {activeOsiLayer.pdu}
              </CidrPill>
            </div>
            <p
              style={{
                fontSize: "13px",
                color: C.text,
                lineHeight: "1.6",
                margin: "0 0 16px",
              }}
            >
              {activeOsiLayer.desc}
            </p>
            <div
              style={{ display: "flex", flexDirection: "column", gap: "10px" }}
            >
              <div>
                <span
                  style={{ fontSize: "11px", fontWeight: 700, color: C.muted }}
                >
                  KEY PROTOCOLS
                </span>
                <div
                  style={{
                    fontSize: "13px",
                    color: C.teal,
                    fontFamily: "'JetBrains Mono', monospace",
                    marginTop: "4px",
                  }}
                >
                  {activeOsiLayer.protocols}
                </div>
              </div>
              <div>
                <span
                  style={{ fontSize: "11px", fontWeight: 700, color: C.muted }}
                >
                  HARDWARE & DEVICES
                </span>
                <div
                  style={{ fontSize: "13px", color: C.amber, marginTop: "4px" }}
                >
                  {activeOsiLayer.devices}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === "ports" && (
        <div>
          <TextInput
            value={portSearch}
            onChange={(e) => setPortSearch(e.target.value)}
            placeholder="Search ports (e.g. 80, SSH, TCP)..."
            style={{ marginBottom: "12px" }}
          />
          <div
            style={{
              borderRadius: "8px",
              overflow: "hidden",
              border: `1px solid ${C.borderSoft}`,
            }}
          >
            <table
              style={{
                width: "100%",
                fontSize: "13px",
                borderCollapse: "collapse",
              }}
            >
              <thead>
                <tr style={{ background: C.panel2 }}>
                  {[
                    "Port #",
                    "Service",
                    "Protocol",
                    "Category",
                    "Description",
                  ].map((h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: "left",
                        fontSize: "11px",
                        color: C.muted,
                        padding: "8px 12px",
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredPorts.map((p) => (
                  <tr
                    key={p.port}
                    style={{ borderTop: `1px solid ${C.borderSoft}` }}
                  >
                    <td style={{ padding: "8px 12px" }}>
                      <CidrPill color={C.teal}>{p.port}</CidrPill>
                    </td>
                    <td
                      style={{
                        padding: "8px 12px",
                        fontWeight: 600,
                        color: C.text,
                      }}
                    >
                      {p.service}
                    </td>
                    <td
                      style={{
                        padding: "8px 12px",
                        color: C.amber,
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {p.proto}
                    </td>
                    <td style={{ padding: "8px 12px", color: C.muted }}>
                      {p.cat}
                    </td>
                    <td
                      style={{
                        padding: "8px 12px",
                        color: C.muted,
                        fontSize: "12px",
                      }}
                    >
                      {p.desc}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------------------------------------------------
   Main component
--------------------------------------------------------- */
const TABS = [
  { id: "ipv4", label: "IPv4 Calculator" },
  { id: "vlsm", label: "Subnet Planner (VLSM / FLSM)" },
  { id: "ipv6", label: "IPv6 Toolkit" },
  { id: "tcp", label: "TCP & Packet Flow" },
  { id: "osi", label: "OSI Model & Ports" },
  { id: "dns", label: "DNS Visualizer" },
  { id: "sec", label: "Security & Devices" },
  { id: "v4v6", label: "IPv4 vs IPv6" },
  { id: "quiz", label: "Subnet Quiz" },
  { id: "reference", label: "CIDR Reference" },
];

const IPV6_SUB_TABS = [
  { id: "info", label: "Subnet Info" },
  { id: "planner", label: "Sub-Prefix Planner" },
  { id: "types", label: "Address Types" },
  { id: "refv6", label: "Quick Reference" },
];

const PALETTE = [C.teal, C.amber, C.violet, C.blue, C.pink, C.green];

export default function SubnetToolkit() {
  const [tab, setTab] = useState("ipv4");
  const [ipv6SubTab, setIpv6SubTab] = useState("info");
  const [plannerMode, setPlannerMode] = useState("vlsm");
  const [exportModalData, setExportModalData] = useState(null);

  /* IPv4 state */
  const [ip, setIp] = useState("192.168.1.10");
  const [cidr, setCidr] = useState("24");
  const ipv4Valid = isValidIPv4(ip) && Number(cidr) >= 0 && Number(cidr) <= 32;
  const ipv4Result = useMemo(
    () => (ipv4Valid ? calcIPv4Subnet(ip, Number(cidr)) : null),
    [ip, cidr, ipv4Valid],
  );
  const ipv4ClassScope = useMemo(
    () => (ipv4Valid ? detectIPv4ClassAndScope(ip) : null),
    [ip, ipv4Valid],
  );

  /* VLSM state */
  const [vlsmBaseIp, setVlsmBaseIp] = useState("192.168.10.0");
  const [vlsmBaseCidr, setVlsmBaseCidr] = useState("24");
  const [vlsmRows, setVlsmRows] = useState([
    { id: 1, name: "Sales", hosts: 50 },
    { id: 2, name: "Engineering", hosts: 25 },
    { id: 3, name: "Guest Wi-Fi", hosts: 10 },
    { id: 4, name: "Point-to-point link", hosts: 2 },
  ]);
  const vlsmValid =
    isValidIPv4(vlsmBaseIp) &&
    Number(vlsmBaseCidr) >= 0 &&
    Number(vlsmBaseCidr) <= 32;
  const vlsmResult = useMemo(
    () =>
      vlsmValid
        ? calculateVLSM(vlsmBaseIp, Number(vlsmBaseCidr), vlsmRows)
        : null,
    [vlsmBaseIp, vlsmBaseCidr, vlsmRows, vlsmValid],
  );

  /* FLSM state */
  const [flsmCount, setFlsmCount] = useState("4");
  const flsmResult = useMemo(
    () =>
      vlsmValid
        ? calculateFLSM(vlsmBaseIp, Number(vlsmBaseCidr), flsmCount)
        : null,
    [vlsmBaseIp, vlsmBaseCidr, flsmCount, vlsmValid],
  );

  function updateRow(id, field, value) {
    setVlsmRows((rows) =>
      rows.map((r) => (r.id === id ? { ...r, [field]: value } : r)),
    );
  }
  function addRow() {
    setVlsmRows((rows) => [
      ...rows,
      { id: Date.now(), name: `Subnet ${rows.length + 1}`, hosts: 10 },
    ]);
  }
  function removeRow(id) {
    setVlsmRows((rows) => rows.filter((r) => r.id !== id));
  }

  /* IPv6 state */
  const [ip6, setIp6] = useState("2001:db8:85a3::8a2e:370:7334");
  const [prefix6, setPrefix6] = useState("64");
  const ipv6Result = useMemo(() => {
    try {
      return calcIPv6Subnet(ip6, Number(prefix6));
    } catch {
      return null;
    }
  }, [ip6, prefix6]);

  function exportIPv4Report() {
    if (!ipv4Result || !ipv4ClassScope) return;
    const text = `================================================
IPv4 SUBNET CALCULATION REPORT
================================================
IP Address       : ${ip}/${cidr}
Class Type       : ${ipv4ClassScope.classType}
Scope            : ${ipv4ClassScope.scope}

Network Address  : ${ipv4Result.network}
Broadcast Address: ${ipv4Result.broadcast}
Subnet Mask      : ${ipv4Result.mask} (/${cidr})
Wildcard Mask    : ${ipv4Result.wildcard}
First Host       : ${ipv4Result.firstHost}
Last Host        : ${ipv4Result.lastHost}
Total Addresses  : ${fmtNum(ipv4Result.totalAddresses)}
Usable Hosts     : ${fmtNum(ipv4Result.usableHosts)}
================================================`;
    setExportModalData({ title: "IPv4 Subnet Report", reportText: text });
  }

  function exportSubnetPlannerReport() {
    if (plannerMode === "vlsm" && vlsmResult) {
      let text = `================================================
VLSM SUBNET PLANNING REPORT
================================================
Base Network: ${vlsmBaseIp}/${vlsmBaseCidr}

ALLOCATED SUBNETS:
`;
      vlsmResult.allocated.forEach((a) => {
        text += `\n- ${a.name}
  Network  : ${a.network}/${a.cidr}
  Host Range: ${a.firstHost} - ${a.lastHost}
  Usable   : ${fmtNum(a.usableHosts)} hosts (Block size: ${a.blockSize})\n`;
      });
      setExportModalData({ title: "VLSM Allocation Report", reportText: text });
    } else if (plannerMode === "flsm" && flsmResult) {
      let text = `================================================
FLSM SUBNET PLANNING REPORT
================================================
Base Network: ${vlsmBaseIp}/${vlsmBaseCidr}
Divided into: ${flsmResult.actualSubnetCount} Equal Subnets (/${flsmResult.newCidr})

ALLOCATED EQUAL SUBNETS:
`;
      flsmResult.allocated.forEach((a) => {
        text += `\nSubnet #${a.index} (${a.name}):
  Network   : ${a.network}/${a.cidr}
  Host Range : ${a.firstHost} - ${a.lastHost}
  Subnet Mask: ${a.mask}
  Usable     : ${fmtNum(a.usableHosts)} hosts\n`;
      });
      setExportModalData({ title: "FLSM Allocation Report", reportText: text });
    }
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        width: "100%",
        background: "linear-gradient(180deg, #0a0e14 0%, #0d1420 100%)",
        display: "flex",
        justifyContent: "center",
        padding: "32px 16px 48px",
        fontFamily: "'Inter', system-ui, sans-serif",
        boxSizing: "border-box",
      }}
    >
      <div style={{ width: "100%", maxWidth: "1040px" }}>
        {/* Header */}
        <div style={{ marginBottom: "20px" }}>
          <h1
            style={{
              fontSize: "24px",
              fontWeight: 800,
              color: "#e2e8f4",
              letterSpacing: "-0.3px",
              margin: "0 0 6px",
            }}
          >
            Computer Networking &amp; Subnetting Suite
          </h1>
          <p style={{ fontSize: "13px", color: "#6b7d94", margin: 0 }}>
            Subnetting tools, IPv6 planner, TCP handshake visualizer, OSI model,
            DNS simulation, &amp; practice quiz.
          </p>
        </div>

        {/* Main Tab Bar */}
        <div
          style={{
            display: "flex",
            gap: "4px",
            background: "#131a24",
            border: "1px solid #1e2a3a",
            borderRadius: "12px",
            padding: "4px",
            marginBottom: "16px",
            overflowX: "auto",
          }}
        >
          {TABS.map((t) => {
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                style={{
                  flex: 1,
                  padding: "8px 10px",
                  borderRadius: "8px",
                  fontSize: "12px",
                  fontWeight: 600,
                  fontFamily: "'Inter', sans-serif",
                  cursor: "pointer",
                  border: "none",
                  whiteSpace: "nowrap",
                  background: active ? "#1ec2ac" : "transparent",
                  color: active ? "#0a0e14" : "#6b7d94",
                }}
              >
                {t.label}
              </button>
            );
          })}
        </div>

        {/* ===== IPv4 TAB ===== */}
        {tab === "ipv4" && (
          <div style={S.panel}>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 180px",
                gap: "16px",
                marginBottom: "16px",
              }}
            >
              <Field label="IP ADDRESS">
                <TextInput
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  placeholder="192.168.1.10"
                />
              </Field>
              <Field label="CIDR">
                <TextInput
                  value={cidr}
                  onChange={(e) => setCidr(e.target.value)}
                  placeholder="24"
                  type="number"
                  min="0"
                  max="32"
                />
              </Field>
            </div>

            {!ipv4Valid && (
              <div
                style={{
                  fontSize: "13px",
                  color: "#e05470",
                  marginBottom: "12px",
                }}
              >
                Enter a valid IPv4 address and a CIDR between 0 and 32.
              </div>
            )}

            {ipv4Result && ipv4ClassScope && (
              <>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "12px",
                    flexWrap: "wrap",
                    gap: "8px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      gap: "8px",
                      alignItems: "center",
                    }}
                  >
                    <Badge color={ipv4ClassScope.classColor}>
                      {ipv4ClassScope.classType}
                    </Badge>
                    <Badge color={ipv4ClassScope.scopeColor}>
                      {ipv4ClassScope.scope}
                    </Badge>
                  </div>
                  <button
                    onClick={exportIPv4Report}
                    style={{
                      padding: "5px 12px",
                      borderRadius: "6px",
                      background: C.tealSoft,
                      color: C.teal,
                      border: `1px solid ${C.teal}40`,
                      fontSize: "12px",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    📥 Export Report
                  </button>
                </div>

                <div style={{ ...S.subPanel, marginBottom: "12px" }}>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr",
                      columnGap: "32px",
                    }}
                  >
                    <StatRow
                      label="Network Address"
                      value={ipv4Result.network}
                      accent="#1ec2ac"
                    />
                    <StatRow
                      label="Broadcast Address"
                      value={ipv4Result.broadcast}
                      accent="#f0962a"
                    />
                    <StatRow label="First Host" value={ipv4Result.firstHost} />
                    <StatRow label="Last Host" value={ipv4Result.lastHost} />
                    <StatRow
                      label="Subnet Mask"
                      value={`${ipv4Result.mask} (/${cidr})`}
                    />
                    <StatRow
                      label="Wildcard Mask"
                      value={ipv4Result.wildcard}
                    />
                    <StatRow
                      label="Total Addresses"
                      value={fmtNum(ipv4Result.totalAddresses)}
                    />
                    <StatRow
                      label="Usable Hosts"
                      value={fmtNum(ipv4Result.usableHosts)}
                      accent="#1ec2ac"
                    />
                  </div>
                </div>

                <div style={{ ...S.subPanel, marginBottom: "12px" }}>
                  <BitBreakdown ip={ipv4Result.network} cidr={Number(cidr)} />
                </div>

                <div style={S.subPanel}>
                  <SectionLabel>NETWORK ARCHITECTURE</SectionLabel>
                  <TopologyDiagram
                    title={`${ipv4Result.network}/${cidr}`}
                    subnets={[
                      {
                        label: "LAN Segment",
                        cidrLabel: `/${cidr}`,
                        range: `${ipv4Result.firstHost} \u2013 ${ipv4Result.lastHost}`,
                        usable: ipv4Result.usableHosts,
                        color: "#1ec2ac",
                      },
                    ]}
                  />
                </div>
              </>
            )}
          </div>
        )}

        {/* ===== SUBNET PLANNER TAB ===== */}
        {tab === "vlsm" && (
          <div style={S.panel}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "16px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  gap: "6px",
                  background: C.panel2,
                  padding: "3px",
                  borderRadius: "8px",
                  border: `1px solid ${C.borderSoft}`,
                }}
              >
                <button
                  onClick={() => setPlannerMode("vlsm")}
                  style={{
                    padding: "5px 14px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    fontWeight: 600,
                    border: "none",
                    cursor: "pointer",
                    background: plannerMode === "vlsm" ? C.teal : "transparent",
                    color: plannerMode === "vlsm" ? "#0a0e14" : C.muted,
                  }}
                >
                  Variable Length (VLSM)
                </button>
                <button
                  onClick={() => setPlannerMode("flsm")}
                  style={{
                    padding: "5px 14px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    fontWeight: 600,
                    border: "none",
                    cursor: "pointer",
                    background: plannerMode === "flsm" ? C.teal : "transparent",
                    color: plannerMode === "flsm" ? "#0a0e14" : C.muted,
                  }}
                >
                  Fixed Length (FLSM)
                </button>
              </div>

              <button
                onClick={exportSubnetPlannerReport}
                style={{
                  padding: "5px 12px",
                  borderRadius: "6px",
                  background: C.tealSoft,
                  color: C.teal,
                  border: `1px solid ${C.teal}40`,
                  fontSize: "12px",
                  fontWeight: 600,
                  cursor: "pointer",
                }}
              >
                📥 Export Report
              </button>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 180px",
                gap: "16px",
                marginBottom: "16px",
              }}
            >
              <Field label="BASE NETWORK">
                <TextInput
                  value={vlsmBaseIp}
                  onChange={(e) => setVlsmBaseIp(e.target.value)}
                  placeholder="192.168.10.0"
                />
              </Field>
              <Field label="BASE CIDR">
                <TextInput
                  value={vlsmBaseCidr}
                  onChange={(e) => setVlsmBaseCidr(e.target.value)}
                  type="number"
                  min="0"
                  max="32"
                />
              </Field>
            </div>

            {plannerMode === "vlsm" && (
              <>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "8px",
                  }}
                >
                  <span style={S.label}>SUBNET REQUIREMENTS</span>
                  <button
                    onClick={addRow}
                    style={{
                      fontSize: "12px",
                      fontWeight: 600,
                      padding: "5px 12px",
                      borderRadius: "7px",
                      background: "rgba(30,194,172,0.13)",
                      color: "#1ec2ac",
                      border: "1px solid rgba(30,194,172,0.3)",
                      cursor: "pointer",
                    }}
                  >
                    + Add subnet
                  </button>
                </div>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px",
                    marginBottom: "16px",
                  }}
                >
                  {vlsmRows.map((row) => (
                    <div
                      key={row.id}
                      style={{
                        display: "flex",
                        gap: "8px",
                        alignItems: "center",
                      }}
                    >
                      <input
                        value={row.name}
                        onChange={(e) =>
                          updateRow(row.id, "name", e.target.value)
                        }
                        placeholder="Segment name"
                        style={{
                          ...S.inputBase,
                          flex: 1,
                          fontFamily: "'Inter', sans-serif",
                        }}
                      />
                      <input
                        value={row.hosts}
                        onChange={(e) =>
                          updateRow(
                            row.id,
                            "hosts",
                            Number(e.target.value) || 0,
                          )
                        }
                        type="number"
                        min="0"
                        placeholder="hosts"
                        style={{ ...S.inputBase, width: "100px" }}
                      />
                      <button
                        onClick={() => removeRow(row.id)}
                        style={{
                          padding: "9px 12px",
                          borderRadius: "8px",
                          border: "1px solid #1e2a3a",
                          background: "transparent",
                          color: "#e05470",
                          cursor: "pointer",
                          fontSize: "13px",
                          lineHeight: 1,
                        }}
                      >
                        &#x2715;
                      </button>
                    </div>
                  ))}
                </div>
                {vlsmResult && vlsmResult.allocated.length > 0 && (
                  <div style={{ ...S.subPanel, overflowX: "auto" }}>
                    <table
                      style={{
                        width: "100%",
                        fontSize: "13px",
                        borderCollapse: "collapse",
                      }}
                    >
                      <thead>
                        <tr>
                          {["Name", "Network", "CIDR", "Range", "Usable"].map(
                            (h) => (
                              <th
                                key={h}
                                style={{
                                  textAlign: "left",
                                  fontSize: "11px",
                                  fontWeight: 600,
                                  color: "#6b7d94",
                                  paddingBottom: "8px",
                                }}
                              >
                                {h}
                              </th>
                            ),
                          )}
                        </tr>
                      </thead>
                      <tbody>
                        {vlsmResult.allocated.map((a, i) => (
                          <tr
                            key={i}
                            style={{ borderTop: "1px solid #19232f" }}
                          >
                            <td style={{ padding: "8px 0", color: "#e2e8f4" }}>
                              {a.name}
                            </td>
                            <td
                              style={{
                                padding: "8px 0",
                                color: PALETTE[i % PALETTE.length],
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {a.network}
                            </td>
                            <td
                              style={{
                                padding: "8px 0",
                                color: "#6b7d94",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              /{a.cidr}
                            </td>
                            <td
                              style={{
                                padding: "8px 0",
                                fontSize: "12px",
                                color: "#6b7d94",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {a.firstHost} &ndash; {a.lastHost}
                            </td>
                            <td
                              style={{
                                padding: "8px 0",
                                color: "#e2e8f4",
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {fmtNum(a.usableHosts)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}

            {plannerMode === "flsm" && (
              <>
                <Field label="NUMBER OF EQUAL SUBNETS">
                  <TextInput
                    value={flsmCount}
                    onChange={(e) => setFlsmCount(e.target.value)}
                    type="number"
                    min="1"
                    max="256"
                    placeholder="4"
                  />
                </Field>
                {flsmResult && flsmResult.allocated.length > 0 && (
                  <div
                    style={{
                      ...S.subPanel,
                      overflowX: "auto",
                      marginTop: "16px",
                    }}
                  >
                    <SectionLabel>
                      EQUAL FLSM SUBNETS (/{flsmResult.newCidr})
                    </SectionLabel>
                    <table
                      style={{
                        width: "100%",
                        fontSize: "13px",
                        borderCollapse: "collapse",
                      }}
                    >
                      <thead>
                        <tr style={{ background: C.panel2 }}>
                          {[
                            "#",
                            "Subnet Name",
                            "Network",
                            "CIDR",
                            "Subnet Mask",
                            "Range",
                            "Usable",
                          ].map((h) => (
                            <th
                              key={h}
                              style={{
                                textAlign: "left",
                                fontSize: "11px",
                                color: C.muted,
                                padding: "8px 12px",
                              }}
                            >
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {flsmResult.allocated.map((a, i) => (
                          <tr
                            key={i}
                            style={{ borderTop: `1px solid ${C.borderSoft}` }}
                          >
                            <td style={{ padding: "8px 12px", color: C.muted }}>
                              {a.index}
                            </td>
                            <td style={{ padding: "8px 12px", color: C.text }}>
                              {a.name}
                            </td>
                            <td
                              style={{
                                padding: "8px 12px",
                                color: PALETTE[i % PALETTE.length],
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {a.network}
                            </td>
                            <td style={{ padding: "8px 12px" }}>
                              <CidrPill color={PALETTE[i % PALETTE.length]}>
                                /{a.cidr}
                              </CidrPill>
                            </td>
                            <td
                              style={{
                                padding: "8px 12px",
                                color: C.muted,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {a.mask}
                            </td>
                            <td
                              style={{
                                padding: "8px 12px",
                                fontSize: "12px",
                                color: C.muted,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {a.firstHost} &ndash; {a.lastHost}
                            </td>
                            <td
                              style={{
                                padding: "8px 12px",
                                color: C.text,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {fmtNum(a.usableHosts)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* ===== IPv6 TOOLKIT TAB ===== */}
        {tab === "ipv6" && (
          <div style={S.panel}>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 180px",
                gap: "16px",
                marginBottom: "16px",
              }}
            >
              <Field label="IPv6 ADDRESS">
                <TextInput
                  value={ip6}
                  onChange={(e) => setIp6(e.target.value)}
                  placeholder="2001:db8:85a3::8a2e:370:7334"
                />
              </Field>
              <Field label="PREFIX LENGTH">
                <TextInput
                  value={prefix6}
                  onChange={(e) => setPrefix6(e.target.value)}
                  type="number"
                  min="0"
                  max="128"
                />
              </Field>
            </div>
            {ipv6Result && (
              <>
                <div
                  style={{
                    display: "flex",
                    gap: "4px",
                    borderBottom: `1px solid ${C.border}`,
                    marginBottom: "16px",
                    overflowX: "auto",
                  }}
                >
                  {IPV6_SUB_TABS.map((st) => (
                    <button
                      key={st.id}
                      onClick={() => setIpv6SubTab(st.id)}
                      style={{
                        padding: "6px 14px",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontWeight: 600,
                        background:
                          ipv6SubTab === st.id ? C.violetSoft : "transparent",
                        color: ipv6SubTab === st.id ? C.violet : C.muted,
                        border: "none",
                        cursor: "pointer",
                      }}
                    >
                      {st.label}
                    </button>
                  ))}
                </div>
                {ipv6SubTab === "info" && (
                  <div style={S.subPanel}>
                    <StatRow
                      label="Expanded Address"
                      value={ipv6Result.expanded}
                    />
                    <StatRow
                      label="Compressed Address"
                      value={ipv6Result.compressed}
                      accent={C.violet}
                    />
                    <StatRow
                      label="Network Prefix"
                      value={`${ipv6Result.networkAddress}/${prefix6}`}
                      accent={C.violet}
                    />
                    <StatRow
                      label="Last Address in Range"
                      value={ipv6Result.lastAddress}
                      accent={C.amber}
                    />
                    <StatRow
                      label="Interface ID Bits"
                      value={`${ipv6Result.hostBits} bits`}
                    />
                    <StatRow
                      label="Total Addresses"
                      value={fmtBigNum(ipv6Result.totalAddresses)}
                    />
                  </div>
                )}
                {ipv6SubTab === "planner" && (
                  <Ipv6SubPrefixPlanner baseAddr={ip6} basePrefix={prefix6} />
                )}
                {ipv6SubTab === "types" && (
                  <Ipv6AddressTypePanel groups={ipv6Result.groups} />
                )}
                {ipv6SubTab === "refv6" && <Ipv6QuickReference />}
              </>
            )}
          </div>
        )}

        {/* ===== TCP & PACKET FLOW TAB ===== */}
        {tab === "tcp" && (
          <div style={S.panel}>
            <TcpVisualizerPanel />
          </div>
        )}

        {/* ===== OSI MODEL & PORTS TAB ===== */}
        {tab === "osi" && (
          <div style={S.panel}>
            <OsiAndPortsPanel />
          </div>
        )}

        {/* ===== NEW MODULE 2: DNS VISUALIZER TAB ===== */}
        {tab === "dns" && (
          <div style={S.panel}>
            <DnsVisualizerPanel />
          </div>
        )}

        {/* ===== NEW MODULE 3 & 4: SECURITY & DEVICES TAB ===== */}
        {tab === "sec" && (
          <div style={S.panel}>
            <SecurityAndDevicesPanel />
          </div>
        )}

        {/* ===== NEW MODULE 5: IPv4 VS IPv6 TAB ===== */}
        {tab === "v4v6" && (
          <div style={S.panel}>
            <Ipv4VsIpv6Matrix />
          </div>
        )}

        {/* ===== NEW MODULE 1: SUBNET QUIZ TAB ===== */}
        {tab === "quiz" && (
          <div style={S.panel}>
            <SubnetQuizPanel />
          </div>
        )}

        {/* ===== CIDR REFERENCE TAB ===== */}
        {tab === "reference" && (
          <div style={S.panel}>
            <SectionLabel>CIDR QUICK REFERENCE</SectionLabel>
            <div
              style={{
                borderRadius: "10px",
                overflow: "hidden",
                border: "1px solid #19232f",
              }}
            >
              <table
                style={{
                  width: "100%",
                  fontSize: "13px",
                  borderCollapse: "collapse",
                }}
              >
                <thead>
                  <tr style={{ background: "#0f1720" }}>
                    {[
                      "CIDR",
                      "Subnet Mask",
                      "Wildcard Mask",
                      "Total Addresses",
                      "Usable Hosts",
                    ].map((h) => (
                      <th
                        key={h}
                        style={{
                          textAlign: "left",
                          fontSize: "11px",
                          fontWeight: 600,
                          color: "#6b7d94",
                          padding: "10px 14px",
                          borderBottom: "1px solid #19232f",
                        }}
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {CIDR_REFERENCE.map((r, idx) => (
                    <tr
                      key={r.cidr}
                      style={{
                        background:
                          idx % 2 === 0
                            ? "transparent"
                            : "rgba(255,255,255,0.015)",
                        borderBottom: "1px solid #19232f",
                      }}
                    >
                      <td style={{ padding: "8px 14px" }}>
                        <CidrPill>/{r.cidr}</CidrPill>
                      </td>
                      <td
                        style={{
                          padding: "8px 14px",
                          color: "#e2e8f4",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {r.mask}
                      </td>
                      <td
                        style={{
                          padding: "8px 14px",
                          color: "#6b7d94",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {r.wildcard}
                      </td>
                      <td
                        style={{
                          padding: "8px 14px",
                          color: "#e2e8f4",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {fmtNum(r.total)}
                      </td>
                      <td
                        style={{
                          padding: "8px 14px",
                          color: "#f0962a",
                          fontFamily: "'JetBrains Mono', monospace",
                          fontWeight: 600,
                        }}
                      >
                        {fmtNum(r.usable)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Modal render */}
        {exportModalData && (
          <ReportExportModal
            title={exportModalData.title}
            reportText={exportModalData.reportText}
            onClose={() => setExportModalData(null)}
          />
        )}
      </div>
    </div>
  );
}
