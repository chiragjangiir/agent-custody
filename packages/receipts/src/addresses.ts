// Addresses that are not the public internet: loopback, private, shared (CGNAT), link-local (cloud metadata), the IETF
// protocol block (Oracle's metadata at 192.0.0.192), benchmarking, multicast, and reserved space, in IPv4 and IPv6,
// IPv4-mapped and NAT64 IPv6 included: an address that embeds an IPv4 address is as internal as that address. Pure, with no Node import, so the browser verifier carries the same list.

const V4: [string, number][] = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 4], ["240.0.0.0", 4],
];
const V6: [string, number][] = [["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["64:ff9b:1::", 48]];

function v4(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    // no leading zeros: `010` is octal to getaddrinfo and an error to Python's ipaddress, so it is not an address here either
    if (!/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

function v6(ip: string): number[] | null {
  let s = ip.toLowerCase();
  // an embedded IPv4 tail (::ffff:10.0.0.1) becomes its two hex groups
  if (s.includes(".")) {
    const at = s.lastIndexOf(":");
    const n = at < 0 ? null : v4(s.slice(at + 1));
    if (n === null) return null;
    s = `${s.slice(0, at + 1)}${Math.floor(n / 65536).toString(16)}:${(n % 65536).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const read = (h: string) => (h === "" ? [] : h.split(":").map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN)));
  const head = read(halves[0]!);
  const rest = halves.length === 2 ? read(halves[1]!) : [];
  const fill = 8 - head.length - rest.length;
  if (halves.length === 1 ? fill !== 0 : fill < 1) return null;
  const groups = [...head, ...Array<number>(halves.length === 2 ? fill : 0).fill(0), ...rest];
  return groups.every((g) => Number.isInteger(g)) ? groups : null;
}

function inV6(g: number[], base: number[], bits: number): boolean {
  for (let i = 0; i < 8 && bits > 0; i++, bits -= 16) {
    const mask = bits >= 16 ? 0xffff : (0xffff << (16 - bits)) & 0xffff;
    if ((g[i]! & mask) !== (base[i]! & mask)) return false;
  }
  return true;
}

/** True when `ip` is not a public address, or is not an address at all: a caller that cannot read it must not dial it. */
export function internalAddress(ip: string): boolean {
  const n = v4(ip);
  if (n !== null) return V4.some(([base, bits]) => Math.floor(n / 2 ** (32 - bits)) === Math.floor(v4(base)! / 2 ** (32 - bits)));
  const g = v6(ip.replace(/^\[|\]$/g, "").replace(/%.*$/, ""));
  if (!g) return true;
  const embedded = embeddedV4(g);
  if (embedded) return internalAddress(embedded);
  return V6.some(([base, bits]) => inV6(g, v6(base)!, bits));
}

/** The IPv4 address inside an IPv4-mapped (::ffff:0:0/96) or NAT64 (64:ff9b::/96) address, else null: a DNS64 answer can wrap an internal IPv4 address. */
function embeddedV4(g: number[]): string | null {
  const mapped = g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff;
  const nat64 = g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0);
  return mapped || nat64 ? `${g[6]! >> 8}.${g[6]! & 255}.${g[7]! >> 8}.${g[7]! & 255}` : null;
}

/** The address in a canonical form (IPv4 dotted, or eight IPv6 groups; a mapped IPv4 address as IPv4), or null when it is not one. */
function canonicalAddress(ip: string): string | null {
  if (v4(ip) !== null) return ip.split(".").map(Number).join(".");
  const g = v6(ip.replace(/^\[|\]$/g, "").replace(/%.*$/, ""));
  if (!g) return null;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return embeddedV4(g);
  return g.map((x) => x.toString(16)).join(":");
}

/** True when `a` and `b` are the same address, written however (::1 and 0:0::1; 10.0.0.1 and ::ffff:10.0.0.1). */
export function sameAddress(a: string, b: string): boolean {
  const x = canonicalAddress(a);
  return x !== null && x === canonicalAddress(b);
}

/** True when `host` is an IP address rather than a name. */
export function isAddressLiteral(host: string): boolean {
  return canonicalAddress(host) !== null;
}
