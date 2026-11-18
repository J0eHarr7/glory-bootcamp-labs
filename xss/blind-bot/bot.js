// Blind-XSS "admin bot": periodically opens the feedback queue the way a
// real admin's browser would, with the admin's session cookie attached,
// and genuinely executes any script the stored page contains (real DOM,
// real fetch, over the real network) via happy-dom's Browser API.
const { Browser } = require("happy-dom");

const TARGET = process.env.TARGET_URL || "http://app:5000";
const ADMIN_TOKEN = process.env.ADMIN_SESSION_TOKEN || "";
const INTERVAL_MS = parseInt(process.env.INTERVAL_MS || "5000", 10);

async function visitOnce() {
  const browser = new Browser({ settings: { enableJavaScriptEvaluation: true, suppressInsecureJavaScriptEnvironmentWarning: true } });
  try {
    const page = browser.newPage();
    page.context.cookieContainer.addCookies([
      { key: "admin_session", value: ADMIN_TOKEN, originURL: new URL(TARGET), path: "/" },
    ]);
    await page.goto(`${TARGET}/admin/queue`);
    await page.waitUntilComplete();
    await new Promise((r) => setTimeout(r, 1500)); // let async fetch()/.then() chains fire
  } finally {
    await browser.close();
  }
  console.log(`[bot] visited ${TARGET}/admin/queue at ${new Date().toISOString()}`);
}

async function loop() {
  while (true) {
    try {
      await visitOnce();
    } catch (e) {
      console.error("[bot] error:", e.message);
    }
    await new Promise((r) => setTimeout(r, INTERVAL_MS));
  }
}

loop();
