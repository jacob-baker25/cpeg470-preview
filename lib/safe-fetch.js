"use strict";

// SSRF-resistant page fetcher used by POST /preview.
//
// Defences, in order:
//   1. Parse the URL server-side; only http: and https: are accepted, and
//      URLs with embedded credentials are rejected.
//   2. If the host is an IP literal, it must be a public unicast address.
//   3. If the host is a name, DNS resolution happens inside a custom `lookup`
//      hook handed to http/https. EVERY resolved address must be public, and
//      the socket connects to exactly the address that was validated, so a
//      second (rebinding) DNS answer can never be used for the connection.
//   4. Redirects are followed manually (max 5); each Location goes through
//      steps 1-3 again before any connection is made.
//   5. One overall deadline covers DNS, connect, redirects and body download,
//      and the decoded body is capped at a fixed number of bytes.

const dns = require("dns");
const http = require("http");
const https = require("https");
const net = require("net");
const zlib = require("zlib");

const DEFAULTS = {
  timeoutMs: 8000,
  maxBytes: 1024 * 1024,
  maxRedirects: 5,
  maxUrlLength: 2048
};

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

class PreviewFetchError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PreviewFetchError";
    this.code = code;
  }
}

// IPv4 special-purpose / non-public ranges (IANA IPv4 Special-Purpose
// Address Registry, RFC 1918, RFC 6598, RFC 5737, multicast, reserved).
const BLOCKED_IPV4 = [
  ["0.0.0.0", 8], // "this network", includes 0.0.0.0
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local, incl. cloud metadata 169.254.169.254
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.88.99.0", 24], // 6to4 relay anycast (deprecated)
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4] // reserved, incl. 255.255.255.255 broadcast
];

// IPv6 is handled as an allowlist: only global unicast 2000::/3 is accepted.
// That alone excludes ::, ::1, IPv4-mapped ::ffff:0:0/96, NAT64 64:ff9b::/96,
// unique-local fc00::/7, link-local fe80::/10, site-local fec0::/10 and
// multicast ff00::/8. Special-purpose blocks inside 2000::/3 are then removed.
const BLOCKED_IPV6_IN_GLOBAL = [
  ["2001::", 23], // IETF protocol assignments (Teredo, benchmarking, ORCHID...)
  ["2001:db8::", 32], // documentation
  ["2002::", 16], // 6to4 (can embed any IPv4 address, including private ones)
  ["3fff::", 20] // documentation (RFC 9637)
];

const blockedV4 = new net.BlockList();
for (const [addr, prefix] of BLOCKED_IPV4) blockedV4.addSubnet(addr, prefix, "ipv4");

const globalV6 = new net.BlockList();
globalV6.addSubnet("2000::", 3, "ipv6");

const blockedV6 = new net.BlockList();
for (const [addr, prefix] of BLOCKED_IPV6_IN_GLOBAL) blockedV6.addSubnet(addr, prefix, "ipv6");

function isPublicAddress(address) {
  const family = net.isIP(String(address));
  try {
    if (family === 4) return !blockedV4.check(address, "ipv4");
    if (family === 6) return globalV6.check(address, "ipv6") && !blockedV6.check(address, "ipv6");
  } catch (_err) {
    // Unparseable (e.g. zone-scoped "fe80::1%eth0") -> not public.
  }
  return false;
}

function blocked() {
  return new PreviewFetchError(
    "BLOCKED_DESTINATION",
    "Destination resolves to a private, local, or reserved network address."
  );
}

function stripBrackets(hostname) {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}

// Parse and validate a URL (optionally relative to `base`, for redirects).
function parseTarget(input, base, isAllowedAddress = isPublicAddress) {
  let url;
  try {
    url = base ? new URL(input, base) : new URL(input);
  } catch (_err) {
    throw new PreviewFetchError("INVALID_URL", "Not a valid absolute URL.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new PreviewFetchError("UNSUPPORTED_PROTOCOL", `Protocol ${url.protocol} is not allowed.`);
  }
  if (url.username || url.password) {
    throw new PreviewFetchError("CREDENTIALS_NOT_ALLOWED", "URLs with credentials are not allowed.");
  }
  const host = stripBrackets(url.hostname);
  if (!host) {
    throw new PreviewFetchError("INVALID_URL", "URL has no host.");
  }
  // Node skips the `lookup` hook entirely for IP literals, so check them here.
  if (net.isIP(host) && !isAllowedAddress(host)) {
    throw blocked();
  }
  url.hash = "";
  return url;
}

function normalizeFamily(family) {
  if (family === 4 || family === "IPv4") return 4;
  if (family === 6 || family === "IPv6") return 6;
  return 0;
}

// Build a dns.lookup-compatible function that refuses to hand back any address
// unless every address the name resolves to is allowed. Because http/https
// pass this function to net.connect, the address validated here is the one
// the socket connects to: there is no second resolution to race against.
function createGuardedLookup(resolve = dns.lookup, isAllowedAddress = isPublicAddress) {
  return function guardedLookup(hostname, options, callback) {
    if (typeof options === "function") {
      callback = options;
      options = {};
    } else if (typeof options === "number") {
      options = { family: options };
    }
    options = options || {};

    resolve(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err) {
        return callback(new PreviewFetchError("DNS_FAILURE", `Could not resolve ${hostname}.`));
      }
      const list = (Array.isArray(addresses) ? addresses : [{ address: addresses }]).map((entry) => ({
        address: entry.address,
        family: normalizeFamily(entry.family) || net.isIP(entry.address)
      }));
      if (list.length === 0) {
        return callback(new PreviewFetchError("DNS_FAILURE", `Could not resolve ${hostname}.`));
      }
      // Reject if ANY record is non-public, so mixed answers can't be abused.
      if (list.some((entry) => !isAllowedAddress(entry.address))) {
        return callback(blocked());
      }
      const family = normalizeFamily(options.family);
      const usable = family ? list.filter((entry) => entry.family === family) : list;
      if (usable.length === 0) {
        return callback(new PreviewFetchError("DNS_FAILURE", `No usable address for ${hostname}.`));
      }
      if (options.all) return callback(null, usable);
      return callback(null, usable[0].address, usable[0].family);
    });
  };
}

function decoderFor(encoding) {
  switch ((encoding || "").trim().toLowerCase()) {
    case "gzip":
    case "x-gzip":
      return zlib.createGunzip();
    case "deflate":
      return zlib.createInflate();
    case "br":
      return zlib.createBrotliDecompress();
    default:
      return null;
  }
}

// Perform a single GET (no redirect following). Resolves with
// { status, location } for redirects, or { status, body, truncated } otherwise.
function requestOnce(url, { lookup, deadline, maxBytes, userAgent }) {
  return new Promise((resolve, reject) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      return reject(new PreviewFetchError("TIMEOUT", "Timed out."));
    }

    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };

    const transport = url.protocol === "https:" ? https : http;
    const req = transport.request(
      url,
      {
        method: "GET",
        agent: false, // fresh connection per request, never a pooled socket
        lookup,
        headers: {
          "User-Agent": userAgent,
          Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
          "Accept-Encoding": "identity"
        }
      },
      (res) => {
        const status = res.statusCode;
        if (REDIRECT_STATUSES.has(status) && res.headers.location) {
          res.resume();
          req.destroy();
          return finish(resolve, { status, location: res.headers.location });
        }

        const decoder = decoderFor(res.headers["content-encoding"]);
        const stream = decoder ? res.pipe(decoder) : res;
        const chunks = [];
        let total = 0;

        const done = (truncated) =>
          finish(resolve, { status, body: Buffer.concat(chunks, total).toString("utf8"), truncated });

        stream.on("data", (chunk) => {
          if (settled) return;
          const room = maxBytes - total;
          if (chunk.length >= room) {
            chunks.push(chunk.subarray(0, room));
            total += room;
            done(true);
            req.destroy(); // stop downloading; nothing past the cap is read
            return;
          }
          chunks.push(chunk);
          total += chunk.length;
        });
        stream.on("end", () => done(false));
        stream.on("error", (err) => finish(reject, err));
        res.on("error", (err) => finish(reject, err));
      }
    );

    // Covers DNS, connect, headers and a slowly dribbled body alike.
    const timer = setTimeout(() => {
      finish(reject, new PreviewFetchError("TIMEOUT", "Timed out."));
      req.destroy();
    }, remaining);

    req.on("error", (err) => finish(reject, err));
    req.end();
  });
}

function createSafeFetch(options = {}) {
  const config = { ...DEFAULTS, ...options };
  const isAllowedAddress = options.isAllowedAddress || isPublicAddress;
  const lookup = createGuardedLookup(options.lookup || dns.lookup, isAllowedAddress);
  const userAgent = options.userAgent || "PreviewBot/1.0 (+link previews)";

  return async function safeFetch(input) {
    const raw = String(input);
    if (raw.length > config.maxUrlLength) {
      throw new PreviewFetchError("INVALID_URL", "URL is too long.");
    }
    let url = parseTarget(raw, undefined, isAllowedAddress);
    const deadline = Date.now() + config.timeoutMs;

    for (let redirects = 0; ; redirects++) {
      const result = await requestOnce(url, {
        lookup,
        deadline,
        maxBytes: config.maxBytes,
        userAgent
      });
      if (result.location === undefined) {
        return { url: url.href, status: result.status, body: result.body, truncated: result.truncated, redirects };
      }
      if (redirects >= config.maxRedirects) {
        throw new PreviewFetchError("TOO_MANY_REDIRECTS", "Too many redirects.");
      }
      // Validate the next hop before connecting to it.
      url = parseTarget(result.location, url, isAllowedAddress);
    }
  };
}

module.exports = {
  DEFAULTS,
  PreviewFetchError,
  createGuardedLookup,
  createSafeFetch,
  isPublicAddress,
  parseTarget,
  safeFetch: createSafeFetch()
};
