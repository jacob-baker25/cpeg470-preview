"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  createSafeFetch,
  createGuardedLookup,
  isPublicAddress,
  parseTarget,
  PreviewFetchError
} = require("../lib/safe-fetch");
const { startFixtureServer, stubLookup, fixturePolicy } = require("./helpers");

function rejectsWith(code) {
  return (err) => {
    assert.ok(err instanceof PreviewFetchError, `expected PreviewFetchError, got ${err && err.stack}`);
    assert.equal(err.code, code);
    return true;
  };
}

// ---------------------------------------------------------------------------
// Address policy
// ---------------------------------------------------------------------------

test("address policy rejects loopback, private, link-local and reserved IPv4", () => {
  const blocked = [
    "0.0.0.0", "0.1.2.3",
    "127.0.0.1", "127.255.255.254",
    "10.0.0.1", "10.255.255.255",
    "172.16.0.1", "172.31.255.255",
    "192.168.0.1", "192.168.255.255",
    "169.254.169.254", "169.254.0.1",
    "100.64.0.1", "100.127.255.255",
    "192.0.0.8", "192.0.2.10", "198.51.100.7", "203.0.113.9",
    "198.18.0.1", "192.88.99.1",
    "224.0.0.1", "239.255.255.250",
    "240.0.0.1", "255.255.255.255"
  ];
  for (const ip of blocked) assert.equal(isPublicAddress(ip), false, ip);
});

test("address policy rejects non-public IPv6, including IPv4-mapped/embedded forms", () => {
  const blocked = [
    "::", "::1",
    "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:10.0.0.1", "::ffff:8.8.8.8",
    "64:ff9b::7f00:1", // NAT64
    "fc00::1", "fd12:3456::1", // unique local
    "fe80::1", "febf::1", // link-local
    "fec0::1", // site-local
    "ff02::1", "ff05::2", // multicast
    "2001:db8::1", // documentation
    "2002:7f00:1::1", "2002:0a00:0001::1", // 6to4 wrapping 127.0.0.1 / 10.0.0.1
    "2001:0:4136:e378::1", // Teredo
    "3fff::1",
    "fe80::1%eth0", // zone id
    "not-an-ip", "", "1.2.3"
  ];
  for (const ip of blocked) assert.equal(isPublicAddress(ip), false, ip);
});

test("address policy accepts ordinary public addresses", () => {
  const allowed = ["8.8.8.8", "1.1.1.1", "93.184.215.14", "128.175.1.1", "172.32.0.1", "100.128.0.1",
    "2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450::1"];
  for (const ip of allowed) assert.equal(isPublicAddress(ip), true, ip);
});

// ---------------------------------------------------------------------------
// URL parsing / protocol checks
// ---------------------------------------------------------------------------

test("rejects malformed and relative URLs", () => {
  for (const input of ["not a url", "example.com", "//example.com", "http://", "http:// spaces .com", "/internal"]) {
    assert.throws(() => parseTarget(input), rejectsWith("INVALID_URL"), input);
  }
});

test("rejects non-HTTP(S) protocols", () => {
  for (const input of [
    "file:///etc/passwd", "ftp://example.com/", "gopher://127.0.0.1:6379/_INFO",
    "data:text/html,<title>x</title>", "javascript:alert(1)", "ws://example.com/", "dict://127.0.0.1:11211/"
  ]) {
    assert.throws(() => parseTarget(input), rejectsWith("UNSUPPORTED_PROTOCOL"), input);
  }
});

test("rejects URLs carrying credentials", () => {
  assert.throws(() => parseTarget("http://user:pass@example.com/"), rejectsWith("CREDENTIALS_NOT_ALLOWED"));
  assert.throws(() => parseTarget("https://admin@example.com/"), rejectsWith("CREDENTIALS_NOT_ALLOWED"));
});

test("rejects IP-literal URLs for non-public hosts, including obfuscated encodings", () => {
  for (const input of [
    "http://127.0.0.1:3000/internal",
    "http://127.1/", "http://0x7f.0.0.1/", "http://2130706433/", "http://017700000001/",
    "http://0.0.0.0:3000/", "http://10.1.2.3/", "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/",
    "http://[::1]:3000/internal", "http://[::ffff:127.0.0.1]/", "http://[0:0:0:0:0:0:0:1]/",
    "http://[fd00::1]/", "http://[fe80::1]/"
  ]) {
    assert.throws(() => parseTarget(input), rejectsWith("BLOCKED_DESTINATION"), input);
  }
});

test("accepts ordinary public http(s) URLs", () => {
  assert.equal(parseTarget("https://example.com/club?x=1#frag").href, "https://example.com/club?x=1");
  assert.equal(parseTarget("http://8.8.8.8/").hostname, "8.8.8.8");
  assert.equal(parseTarget("HTTPS://EXAMPLE.edu").href, "https://example.edu/");
});

test("rejects overly long URLs", async () => {
  const fetchPage = createSafeFetch({ lookup: stubLookup({}) });
  await assert.rejects(fetchPage("http://example.com/" + "a".repeat(3000)), rejectsWith("INVALID_URL"));
});

// ---------------------------------------------------------------------------
// DNS resolution checks (stubbed resolver, production address policy)
// ---------------------------------------------------------------------------

test("rejects hostnames that resolve to non-public addresses", async () => {
  const lookup = stubLookup({
    "localhost": ["127.0.0.1", "::1"],
    "intranet.test": "10.0.0.7",
    "metadata.test": "169.254.169.254",
    "v6local.test": "::1",
    "mapped.test": "::ffff:192.168.0.1",
    "ula.test": "fd00::abcd",
    "zero.test": "0.0.0.0"
  });
  const fetchPage = createSafeFetch({ lookup }); // default (production) policy
  for (const host of Object.keys({ localhost: 1, "intranet.test": 1, "metadata.test": 1, "v6local.test": 1, "mapped.test": 1, "ula.test": 1, "zero.test": 1 })) {
    await assert.rejects(fetchPage(`http://${host}/`), rejectsWith("BLOCKED_DESTINATION"), host);
  }
});

test("rejects a hostname if ANY of its records is non-public", async () => {
  const lookup = stubLookup({ "mixed.test": ["93.184.215.14", "127.0.0.1"] });
  const fetchPage = createSafeFetch({ lookup });
  await assert.rejects(fetchPage("http://mixed.test/"), rejectsWith("BLOCKED_DESTINATION"));
});

test("reports unresolvable hostnames as DNS failures", async () => {
  const fetchPage = createSafeFetch({ lookup: stubLookup({}) });
  await assert.rejects(fetchPage("http://does-not-exist.test/"), rejectsWith("DNS_FAILURE"));
});

test("the original exploit (preview of the app's own loopback address) is blocked by the production policy", async (t) => {
  const fixture = await startFixtureServer();
  t.after(fixture.close);
  const lookup = stubLookup({ localhost: ["127.0.0.1"] });
  const fetchPage = createSafeFetch({ lookup });
  await assert.rejects(fetchPage(`http://127.0.0.1:${fixture.port}/page`), rejectsWith("BLOCKED_DESTINATION"));
  await assert.rejects(fetchPage(`http://localhost:${fixture.port}/page`), rejectsWith("BLOCKED_DESTINATION"));
});

test("guarded lookup returns only validated addresses in both single and `all` modes", async () => {
  const lookup = createGuardedLookup(stubLookup({ "pub.test": ["93.184.215.14", "2606:4700::1"] }));
  const single = await new Promise((res, rej) =>
    lookup("pub.test", { family: 6 }, (err, address, family) => (err ? rej(err) : res({ address, family })))
  );
  assert.deepEqual(single, { address: "2606:4700::1", family: 6 });
  const all = await new Promise((res, rej) => lookup("pub.test", { all: true }, (err, list) => (err ? rej(err) : res(list))));
  assert.deepEqual(all.map((a) => a.address), ["93.184.215.14", "2606:4700::1"]);
});

test("DNS rebinding: one resolution per connection, and the validated address is the one used", async (t) => {
  const fixture = await startFixtureServer();
  t.after(fixture.close);
  // First answer is the (allowed) fixture; any later answer would be private.
  const lookup = stubLookup({ "rebind.test": (n) => (n === 1 ? "127.0.0.1" : "10.0.0.9") });
  const fetchPage = createSafeFetch({ lookup, isAllowedAddress: fixturePolicy });
  const result = await fetchPage(`http://rebind.test:${fixture.port}/page`);
  assert.equal(result.status, 200);
  assert.match(result.body, /Robotics Club/);
  assert.equal(lookup.calls.length, 1, "hostname must be resolved exactly once for the connection");

  // And if the private answer comes first, nothing is fetched.
  const lookup2 = stubLookup({ "rebind.test": (n) => (n === 1 ? "10.0.0.9" : "127.0.0.1") });
  const fetchPage2 = createSafeFetch({ lookup: lookup2, isAllowedAddress: fixturePolicy });
  await assert.rejects(fetchPage2(`http://rebind.test:${fixture.port}/page`), rejectsWith("BLOCKED_DESTINATION"));
  assert.equal(lookup2.calls.length, 1);
});

// ---------------------------------------------------------------------------
// Fetching through fixtures: success, redirects, timeouts, size limits
// ---------------------------------------------------------------------------

async function fixtureFetcher(t, extra = {}) {
  const fixture = await startFixtureServer();
  t.after(fixture.close);
  const lookup = stubLookup({
    "public.test": "127.0.0.1", // stands in for a public site
    "internal.test": "192.168.10.20" // a private host
  });
  const fetchPage = createSafeFetch({ lookup, isAllowedAddress: fixturePolicy, ...extra });
  return { fetchPage, base: `http://public.test:${fixture.port}`, lookup };
}

test("fetches a normal page", async (t) => {
  const { fetchPage, base } = await fixtureFetcher(t);
  const result = await fetchPage(`${base}/page`);
  assert.equal(result.status, 200);
  assert.equal(result.truncated, false);
  assert.match(result.body, /<title>Robotics Club<\/title>/);
});

test("follows relative and absolute redirects to public destinations", async (t) => {
  const { fetchPage, base } = await fixtureFetcher(t);
  const rel = await fetchPage(`${base}/redirect-relative`);
  assert.equal(rel.status, 200);
  assert.equal(rel.redirects, 1);
  assert.match(rel.body, /Robotics Club/);

  const abs = await fetchPage(`${base}/redirect-public`);
  assert.equal(abs.status, 200);
  assert.match(abs.url, /\/page$/);

  const chain = await fetchPage(`${base}/chain/3`); // 4 hops + final, within the limit of 5
  assert.equal(chain.status, 200);
  assert.equal(chain.redirects, 4);
});

test("rejects redirects to private, metadata, loopback and non-HTTP destinations", async (t) => {
  const { fetchPage, base, lookup } = await fixtureFetcher(t);
  await assert.rejects(fetchPage(`${base}/redirect-private-literal`), rejectsWith("BLOCKED_DESTINATION"));
  await assert.rejects(fetchPage(`${base}/redirect-metadata`), rejectsWith("BLOCKED_DESTINATION"));
  await assert.rejects(fetchPage(`${base}/redirect-ipv6-loopback`), rejectsWith("BLOCKED_DESTINATION"));
  await assert.rejects(fetchPage(`${base}/redirect-file`), rejectsWith("UNSUPPORTED_PROTOCOL"));
  await assert.rejects(fetchPage(`${base}/redirect-private-name`), rejectsWith("BLOCKED_DESTINATION"));
  assert.ok(lookup.calls.includes("internal.test"), "redirect hostname must be re-resolved and checked");
});

test("enforces the redirect limit", async (t) => {
  const { fetchPage, base } = await fixtureFetcher(t, { maxRedirects: 5 });
  await assert.rejects(fetchPage(`${base}/loop`), rejectsWith("TOO_MANY_REDIRECTS"));
  await assert.rejects(fetchPage(`${base}/chain/5`), rejectsWith("TOO_MANY_REDIRECTS")); // needs 6 hops
});

test("times out a server that never responds", async (t) => {
  const { fetchPage, base } = await fixtureFetcher(t, { timeoutMs: 300 });
  const started = Date.now();
  await assert.rejects(fetchPage(`${base}/hang`), rejectsWith("TIMEOUT"));
  assert.ok(Date.now() - started < 2000, "timeout should fire promptly");
});

test("times out a body that is dribbled slowly (slowloris-style)", async (t) => {
  const { fetchPage, base } = await fixtureFetcher(t, { timeoutMs: 400 });
  const started = Date.now();
  await assert.rejects(fetchPage(`${base}/slow-body`), rejectsWith("TIMEOUT"));
  assert.ok(Date.now() - started < 2000);
});

test("caps the response body size and stops downloading", async (t) => {
  const { fetchPage, base } = await fixtureFetcher(t, { maxBytes: 64 * 1024 });
  const result = await fetchPage(`${base}/huge`);
  assert.equal(result.truncated, true);
  assert.equal(Buffer.byteLength(result.body), 64 * 1024);
  assert.match(result.body, /<title>Huge<\/title>/);
});

test("caps decompressed size for compressed responses (gzip bomb)", async (t) => {
  const { fetchPage, base } = await fixtureFetcher(t, { maxBytes: 128 * 1024 });
  const result = await fetchPage(`${base}/gzip-bomb`);
  assert.equal(result.truncated, true);
  assert.equal(Buffer.byteLength(result.body), 128 * 1024);
});
