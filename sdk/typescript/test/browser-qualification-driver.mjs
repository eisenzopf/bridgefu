import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const baseUrl = process.env.BRIDGEFU_BROWSER_QUALIFICATION_URL;
const standardcharterWeb = process.env.BRIDGEFU_STANDARDCHARTER_WEB;
if (!baseUrl) throw new Error("BRIDGEFU_BROWSER_QUALIFICATION_URL is required");
if (!standardcharterWeb) throw new Error("BRIDGEFU_STANDARDCHARTER_WEB is required");

const requireFromStandardcharter = createRequire(resolve(standardcharterWeb, "package.json"));
const { chromium } = requireFromStandardcharter("playwright");
const executablePath = chromium.executablePath();
if (!existsSync(executablePath)) {
  throw new Error(
    `Playwright Chromium is absent at ${executablePath}; install the pinned StandardCharter browser first`,
  );
}

const browser = await chromium.launch({
  headless: true,
  args: [
    "--use-fake-ui-for-media-stream",
    "--use-fake-device-for-media-stream",
    "--autoplay-policy=no-user-gesture-required",
    "--no-sandbox",
  ],
});

try {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    permissions: ["microphone"],
  });
  const page = await context.newPage();
  page.on("console", (message) => {
    process.stderr.write(`[chromium:${message.type()}] ${message.text()}\n`);
  });
  page.on("pageerror", (error) => {
    process.stderr.write(`[chromium:pageerror] ${error.stack ?? error}\n`);
  });
  await page.goto(baseUrl, { waitUntil: "load", timeout: 20_000 });
  await page.waitForFunction(() => Boolean(window.__bridgefuQualification), null, {
    timeout: 10_000,
  });
  const result = await page.evaluate(() => window.__bridgefuQualification);
  process.stdout.write(`BRIDGEFU_BROWSER_RESULT=${JSON.stringify(result)}\n`);
  await context.close();
} finally {
  await browser.close();
}
