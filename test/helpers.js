"use strict";

// Shared fixtures for the SSRF regression tests.
//
// A local HTTP server on 127.0.0.1 stands in for "a public website". The
// guarded fetcher would (correctly) refuse to connect to 127.0.0.1, so tests
// that need to reach the fixture use:
//   - a stubbed DNS resolver mapping fake names (e.g. public.test) to IPs, and
//   - an address policy that is the real isPublicAddress() policy plus exactly
//     one exception: the fixture address 127.0.0.1.
// Every other address (10/8, 169.254/16, ::1, ...) is still judged by the
// production policy, and no test touches a real external or private service.

const http = require("http");
const zlib = require("zlib");
const { isPublicAddress } = require("../lib/safe-fetch");

const FIXTURE_IP = "127.0.0.1";

function startFixtureServer() {
  const server = http.createServer((req, res) => {
    const port = server.address().port;
    const path = req.url;

    if (path === "/page") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(
        "<html><head><title>Robotics Club</title></head><body><script>ignored()</script><p>Meetings every Tuesday in the shop.</p></body></html>"
      );
    }
    if (path === "/xss") {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end('<title>Club "A" & B > C</title><p>x" onmouseover="alert(1) &amp; more</p>');
    }
    if (path === "/redirect-relative") {
      res.writeHead(302, { Location: "/page" });
      return res.end();
    }
    if (path === "/redirect-public") {
      res.writeHead(301, { Location: `http://public.test:${port}/page` });
      return res.end();
    }
    if (path === "/redirect-private-literal") {
      res.writeHead(302, { Location: "http://10.0.0.5/admin" });
      return res.end();
    }
    if (path === "/redirect-metadata") {
      res.writeHead(307, { Location: "http://169.254.169.254/latest/meta-data/" });
      return res.end();
    }
    if (path === "/redirect-ipv6-loopback") {
      res.writeHead(302, { Location: `http://[::1]:${port}/page` });
      return res.end();
    }
    if (path === "/redirect-private-name") {
      res.writeHead(302, { Location: `http://internal.test:${port}/page` });
      return res.end();
    }
    if (path === "/redirect-file") {
      res.writeHead(302, { Location: "file:///etc/passwd" });
      return res.end();
    }
    if (path.startsWith("/loop")) {
      const n = Number(new URL(path, "http://x").searchParams.get("n") || 0);
      res.writeHead(302, { Location: `/loop?n=${n + 1}` });
      return res.end();
    }
    if (path.startsWith("/chain/")) {
      // /chain/3 -> /chain/2 -> /chain/1 -> /chain/0 -> /page
      const n = Number(path.split("/")[2]);
      res.writeHead(302, { Location: n > 0 ? `/chain/${n - 1}` : "/page" });
      return res.end();
    }
    if (path === "/hang") {
      return; // never respond
    }
    if (path === "/slow-body") {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.write("<title>Slow</title>");
      const t = setInterval(() => res.write("."), 50);
      res.on("close", () => clearInterval(t));
      return;
    }
    if (path === "/huge") {
      // 5 MB body, streamed. The fetcher must stop well before the end.
      res.writeHead(200, { "Content-Type": "text/html" });
      res.write("<title>Huge</title>");
      const chunk = Buffer.alloc(64 * 1024, "a");
      let sent = 0;
      const pump = () => {
        while (sent < 5 * 1024 * 1024) {
          sent += chunk.length;
          if (!res.write(chunk)) return res.once("drain", pump);
        }
        res.end();
      };
      res.on("error", () => {});
      return pump();
    }
    if (path === "/gzip-bomb") {
      // ~10 KB on the wire, 20 MB once decompressed.
      const bomb = zlib.gzipSync(Buffer.alloc(20 * 1024 * 1024, 0));
      res.writeHead(200, { "Content-Type": "text/html", "Content-Encoding": "gzip" });
      return res.end(bomb);
    }
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("not found");
  });

  // Track sockets so close() never waits on the hanging routes.
  const sockets = new Set();
  server.on("connection", (s) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
  });

  return new Promise((resolve) => {
    server.listen(0, FIXTURE_IP, () => {
      resolve({
        server,
        port: server.address().port,
        close: () =>
          new Promise((done) => {
            for (const s of sockets) s.destroy();
            server.close(() => done());
          })
      });
    });
  });
}

// Stubbed dns.lookup. `table` maps hostname -> address or [addresses].
// Records every call so tests can assert how many resolutions happened.
function stubLookup(table) {
  const calls = [];
  function lookup(hostname, _options, callback) {
    calls.push(hostname);
    let entry = table[hostname];
    if (typeof entry === "function") entry = entry(calls.filter((h) => h === hostname).length);
    if (entry === undefined) {
      const err = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
      err.code = "ENOTFOUND";
      return process.nextTick(callback, err);
    }
    const list = (Array.isArray(entry) ? entry : [entry]).map((address) => ({
      address,
      family: address.includes(":") ? 6 : 4
    }));
    process.nextTick(callback, null, list);
  }
  lookup.calls = calls;
  return lookup;
}

// Production policy, plus the single fixture address.
function fixturePolicy(address) {
  return address === FIXTURE_IP || isPublicAddress(address);
}

module.exports = { FIXTURE_IP, startFixtureServer, stubLookup, fixturePolicy };
