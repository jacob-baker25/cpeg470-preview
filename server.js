const express = require("express");
const path = require("path");
const { safeFetch } = require("./lib/safe-fetch");

const app = express();
// Outbound fetcher for /preview. Tests may swap in a fetcher configured with
// fixtures; production always uses the SSRF-guarded default.
app.locals.fetchPage = safeFetch;
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

const saved = [
  {
    url: "https://example.edu/robotics",
    title: "Robotics club",
    snippet: "Shop hours, ride board, and the missing hex-driver thread."
  },
  {
    url: "https://example.edu/film",
    title: "Film society",
    snippet: "Thursday screening in the basement theater. Bring a chair."
  }
];

function extract(html) {
  const title = (html.match(/<title>([^<]*)<\/title>/i) || [, ""])[1].trim();
  const text = html.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  return {
    title: title || text.slice(0, 60) || "Untitled",
    snippet: text.slice(0, 240)
  };
}

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/preview", async (req, res) => {
  const url = String(req.body.url || "").trim();
  if (!url) {
    return res.status(400).send(page("Paste a URL.", saved, null));
  }
  try {
    const response = await req.app.locals.fetchPage(url);
    const card = { url, ...extract(response.body), status: response.status };
    res.send(page(null, saved, card));
  } catch (err) {
    const [status, message] = FETCH_ERRORS[err && err.code] || [502, "Could not fetch that URL."];
    if (err && err.code === "BLOCKED_DESTINATION") {
      console.warn(`Blocked preview request to non-public destination: ${JSON.stringify(url.slice(0, 200))}`);
    }
    res.status(status).send(page(message, saved, null));
  }
});

// Maps PreviewFetchError codes from lib/safe-fetch.js to responses.
const FETCH_ERRORS = {
  INVALID_URL: [400, "That is not a valid URL. Use a full http:// or https:// address."],
  UNSUPPORTED_PROTOCOL: [400, "Only http:// and https:// URLs can be previewed."],
  CREDENTIALS_NOT_ALLOWED: [400, "URLs containing a username or password cannot be previewed."],
  BLOCKED_DESTINATION: [
    403,
    "That URL points to a private, local, or reserved network address, so Preview will not fetch it."
  ],
  TOO_MANY_REDIRECTS: [502, "That URL redirected too many times."],
  DNS_FAILURE: [502, "Could not find that website. Check the hostname."],
  TIMEOUT: [504, "That website took too long to respond."]
};

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function page(error, cards, fresh) {
  const list = cards
    .map(
      (card) => `<article class="card"><h2>${escapeHtml(card.title)}</h2><p>${escapeHtml(card.snippet)}</p><p class="url">${escapeHtml(card.url)}</p></article>`
    )
    .join("");
  const result = fresh
    ? `<article class="card fresh"><p class="status">${fresh.status}</p><h2>${escapeHtml(fresh.title)}</h2><p>${escapeHtml(fresh.snippet)}</p><p class="url">${escapeHtml(fresh.url)}</p></article>`
    : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Preview</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <div class="shell">
    <header class="top">
      <a class="brand" href="/"><span class="mark">Pv</span><span><strong>Preview</strong><em>Club link cards</em></span></a>
    </header>
    <main>
      <section class="hero">
        <h1>Paste a club URL. Get a card.</h1>
        <p class="lede">Preview fetches the page and keeps the title and the first lines. No account required.</p>
      </section>
      <form method="post" action="/preview" class="stack">
        <label><span>URL</span><input name="url" type="url" placeholder="https://..." required></label>
        <button type="submit">Preview</button>
      </form>
      ${error ? `<p class="flash">${escapeHtml(error)}</p>` : ""}
      ${result}
      <h2 class="section">Saved cards</h2>
      ${list}
    </main>
    <footer>Preview is unofficial. It only reads what the URL returns.</footer>
  </div>
</body>
</html>`;
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, "0.0.0.0", () => {
    console.log(`Preview listening on ${port}`);
  });
}

module.exports = app;
