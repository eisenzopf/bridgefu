import { existsSync } from "node:fs";

const baseUrl = process.env.BRIDGEFU_BROWSER_QUALIFICATION_URL;
if (!baseUrl) throw new Error("BRIDGEFU_BROWSER_QUALIFICATION_URL is required");

process.env.PLAYWRIGHT_BROWSERS_PATH ??= "0";
const { chromium } = await import("playwright");
const executablePath = chromium.executablePath();
if (!existsSync(executablePath)) {
  throw new Error(
    `Playwright Chromium is absent at ${executablePath}; run npm run browser:install in sdk/typescript`,
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
