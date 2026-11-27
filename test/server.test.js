"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const app = require("../server");
const { safeFetch, createSafeFetch } = require("../lib/safe-fetch");
const { startFixtureServer, stubLookup, fixturePolicy } = require("./helpers");

let server;
let base;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => new Promise((resolve) => server.close(resolve)));

// Every test starts from the production fetcher unless it opts in to fixtures.
test.beforeEach(() => {
  app.locals.fetchPage = safeFetch;
});

function preview(url) {
  return fetch(`${base}/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ url }).toString()
  });
}

test("homepage still renders", async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /Paste a club URL/);
  assert.match(html, /Robotics club/);
});

test("stylesheet is still served", async () => {
  const res = await fetch(`${base}/styles.css`);
  assert.equal(res.status, 200);
});

test("/health still works", async () => {
  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
});

test("/internal endpoint and its desk note are gone", async () => {
  const res = await fetch(`${base}/internal`);
  assert.equal(res.status, 404);
  const body = await res.text();
  assert.doesNotMatch(body, /PREVIEW-4418|Desk note/);
});

test("empty URL still gets the original message", async () => {
  const res = await preview("   ");
  assert.equal(res.status, 400);
  assert.match(await res.text(), /Paste a URL\./);
});

test("invalid URL is rejected with 400 and a clear message", async () => {
  const res = await preview("not a url");
  assert.equal(res.status, 400);
  assert.match(await res.text(), /not a valid URL/);
});

test("unsupported protocol is rejected with 400", async () => {
  const res = await preview("file:///etc/passwd");
  assert.equal(res.status, 400);
  assert.match(await res.text(), /Only http:\/\/ and https:\/\/ URLs/);
});

test("the original SSRF payload (this server's own /internal via loopback) is refused with 403", async (t) => {
  t.mock.method(console, "warn", () => {});
  for (const target of [`${base}/internal`, `http://[::1]:${server.address().port}/internal`, "http://169.254.169.254/latest/meta-data/"]) {
    const res = await preview(target);
    assert.equal(res.status, 403, target);
    const html = await res.text();
    assert.match(html, /private, local, or reserved network address/);
    assert.doesNotMatch(html, /PREVIEW-4418/);
  }
});

test("a hostname resolving to a private address is refused through the route", async (t) => {
  t.mock.method(console, "warn", () => {});
  app.locals.fetchPage = createSafeFetch({ lookup: stubLookup({ "intranet.test": "10.20.30.40" }) });
  const res = await preview("http://intranet.test/");
  assert.equal(res.status, 403);
  assert.match(await res.text(), /private, local, or reserved/);
});

test("a normal public page still produces a preview card (with redirect)", async (t) => {
  const fixture = await startFixtureServer();
  t.after(fixture.close);
  app.locals.fetchPage = createSafeFetch({
    lookup: stubLookup({ "club.test": "127.0.0.1" }),
    isAllowedAddress: fixturePolicy
  });
  const url = `http://club.test:${fixture.port}/redirect-relative`;
  const res = await preview(url);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /<article class="card fresh"><p class="status">200<\/p><h2>Robotics Club<\/h2>/);
  assert.match(html, /Meetings every Tuesday in the shop\./);
  assert.doesNotMatch(html, /ignored\(\)/, "script contents are still stripped");
  assert.ok(html.includes(url), "card shows the submitted URL");
});

test("HTML escaping of fetched content is preserved", async (t) => {
  const fixture = await startFixtureServer();
  t.after(fixture.close);
  app.locals.fetchPage = createSafeFetch({
    lookup: stubLookup({ "club.test": "127.0.0.1" }),
    isAllowedAddress: fixturePolicy
  });
  const res = await preview(`http://club.test:${fixture.port}/xss`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /<h2>Club &quot;A&quot; &amp; B &gt; C<\/h2>/);
  assert.match(html, /x&quot; onmouseover=&quot;alert\(1\) &amp;amp; more/);
  assert.doesNotMatch(html, /onmouseover="alert/);
});

test("timeouts surface as 504", async (t) => {
  const fixture = await startFixtureServer();
  t.after(fixture.close);
  app.locals.fetchPage = createSafeFetch({
    lookup: stubLookup({ "club.test": "127.0.0.1" }),
    isAllowedAddress: fixturePolicy,
    timeoutMs: 300
  });
  const res = await preview(`http://club.test:${fixture.port}/hang`);
  assert.equal(res.status, 504);
  assert.match(await res.text(), /took too long/);
});

test("redirect loops surface as 502", async (t) => {
  const fixture = await startFixtureServer();
  t.after(fixture.close);
  app.locals.fetchPage = createSafeFetch({
    lookup: stubLookup({ "club.test": "127.0.0.1" }),
    isAllowedAddress: fixturePolicy
  });
  const res = await preview(`http://club.test:${fixture.port}/loop`);
  assert.equal(res.status, 502);
  assert.match(await res.text(), /redirected too many times/);
});
