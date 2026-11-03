#!/usr/bin/env node
/**
 * Cross-portfolio SEO health check.
 * Verifies robots, sitemap XML, every sitemap URL, canonical, title/H1, and JSON-LD.
 * No dependencies; exits non-zero on any failure.
 */
const SITES = [
  { host: 'aml-filter.com', expectLang: null },
  { host: 'edge-reco.com', expectLang: null },
  { host: 'almamesh.com', expectLang: 'en' },
  { host: 'open-source.gainratio.com', expectLang: 'en' },
  { host: 'gainratio.com', expectLang: 'en' },
];

const failures = [];
const results = [];
const timeout = (ms) => AbortSignal.timeout(ms);

async function fetchText(url) {
  const response = await fetch(url, {
    headers: { 'user-agent': 'GainRatio-SEO-Health/1.0 (+https://gainratio.com)' },
    signal: timeout(25_000),
  });
  const body = await response.text();
  return { status: response.status, type: response.headers.get('content-type') ?? '', body, url: response.url };
}

function fail(site, url, message) {
  failures.push({ site, url, message });
}

for (const site of SITES) {
  const base = `https://${site.host}`;
  const summary = { host: site.host, robots: 0, sitemap: 0, urls: 0, checked: 0, failed: 0 };
  try {
    const robots = await fetchText(`${base}/robots.txt`);
    summary.robots = robots.status;
    if (robots.status !== 200) fail(site.host, `${base}/robots.txt`, `HTTP ${robots.status}`);
    if (!robots.body.toLowerCase().includes('sitemap:')) fail(site.host, `${base}/robots.txt`, 'no Sitemap directive');

    const sitemap = await fetchText(`${base}/sitemap.xml`);
    summary.sitemap = sitemap.status;
    if (sitemap.status !== 200) fail(site.host, `${base}/sitemap.xml`, `HTTP ${sitemap.status}`);
    const locs = [...sitemap.body.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
    summary.urls = locs.length;
    if (locs.length === 0) fail(site.host, `${base}/sitemap.xml`, 'no <loc> entries');

    for (const url of locs) {
      summary.checked += 1;
      try {
        const page = await fetchText(url);
        if (page.status !== 200) { fail(site.host, url, `HTTP ${page.status}`); summary.failed += 1; continue; }
        if (!page.type.includes('text/html')) { fail(site.host, url, `content-type ${page.type}`); summary.failed += 1; continue; }
        const html = page.body;
        const canonical = html.match(/<link[^>]+rel="canonical"[^>]+href="([^"]+)"/i)?.[1]
          ?? html.match(/<link[^>]+href="([^"]+)"[^>]+rel="canonical"/i)?.[1];
        if (!canonical) fail(site.host, url, 'missing canonical');
        else if (canonical.replace(/\/$/, '') !== url.replace(/\/$/, '')) fail(site.host, url, `canonical ${canonical}`);
        const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim() ?? '';
        if (title.length < 10) fail(site.host, url, 'missing/short title');
        const h1s = [...html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi)];
        if (h1s.length !== 1) fail(site.host, url, `H1 count ${h1s.length}`);
        const blocks = [...html.matchAll(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)];
        for (const block of blocks) {
          try { JSON.parse(block[1]); } catch { fail(site.host, url, 'invalid JSON-LD'); }
        }
        if (site.expectLang) {
          const lang = html.match(/<html[^>]+lang="([^"]+)"/i)?.[1];
          if (!lang) fail(site.host, url, 'missing html lang');
        }
        if (/\/hi\//.test(url)) {
          for (const code of ['en', 'hi', 'x-default']) {
            if (!html.includes(`hreflang="${code}"`)) fail(site.host, url, `missing hreflang ${code}`);
          }
        }
      } catch (error) {
        fail(site.host, url, error.name === 'TimeoutError' ? 'timeout' : String(error));
        summary.failed += 1;
      }
    }
  } catch (error) {
    fail(site.host, base, String(error));
  }
  results.push(summary);
}

console.table(results);
if (failures.length) {
  console.error(`\n${failures.length} failure(s):`);
  for (const failure of failures) console.error(`- ${failure.site} ${failure.url}: ${failure.message}`);
  process.exit(1);
}
console.log('\nAll portfolio SEO checks passed.');
