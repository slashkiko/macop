#!/usr/bin/env node
// Render the images README.md embeds, so they are never stale: export.sh wipes
// png/ on every run, and a README pointing at a deleted screenshot is worse
// than one with no screenshot.
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1120, height: 800 } });

  await page.goto('file://' + __dirname + '/preview.html');
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: 'png/overview.png', fullPage: true });
  console.log('  png/overview.png');

  await browser.close();
})();
