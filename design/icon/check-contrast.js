#!/usr/bin/env node
// Measure keyway-vs-glass contrast for every theme and fail if any falls under
// the target. The die face is translucent, so a palette edit can quietly make
// the mark unreadable; this is what stops that shipping.
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const KEY_TARGET = 5.5;   // keyway vs the window behind it
const DIE_TARGET = 1.75;  // die wall vs the sky beside it -- glass you cannot see is not glass
const THEMES = execFileSync('python3', ['-c', 'import build; print(" ".join(build.THEMES))'],
  { cwd: __dirname, encoding: 'utf8' }).trim().split(/\s+/);

const lum = ([r, g, b]) => { const f = c => { c /= 255; return c <= .03928 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4; };
  return .2126 * f(r) + .7152 * f(g) + .0722 * f(b); };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + .05) / (y + .05); };

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 300, height: 300 } });
  let bad = 0;
  for (const theme of THEMES) {
    const svg = execFileSync('python3', ['-c', 'import build; print(build.app_icon())'],
      { cwd: __dirname, encoding: 'utf8', env: { ...process.env, MACOP_THEME: theme } });
    await page.setContent('<style>body{margin:0}svg{width:256px;height:256px;display:block}</style>' + svg);
    const px = await page.evaluate(async () => {
      const s = new XMLSerializer().serializeToString(document.querySelector('svg'));
      const img = new Image();
      img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(s)));
      await img.decode();
      const c = document.createElement('canvas'); c.width = c.height = 256;
      const x = c.getContext('2d'); x.drawImage(img, 0, 0, 256, 256);
      // 0.38/0.50 glass beside the ward, 0.485/0.44 inside the eye,
      // 0.305/0.44 mid-wall, 0.255/0.44 the sky just outside it (no pin there).
      const at = (fx, fy) => [...x.getImageData(Math.round(fx * 256), Math.round(fy * 256), 1, 1).data].slice(0, 3);
      return { glass: at(0.38, 0.50), key: at(0.485, 0.44), wall: at(0.305, 0.44), sky: at(0.255, 0.44) };
    });
    const key = ratio(px.glass, px.key);
    const die = ratio(px.wall, px.sky);
    const ok = key >= KEY_TARGET && die >= DIE_TARGET;
    if (!ok) bad++;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${theme.padEnd(10)} keyway ${key.toFixed(2)}:1   die ${die.toFixed(2)}:1`);
  }
  await browser.close();
  if (bad) {
    console.error(`\n${bad} theme(s) short: keyway needs ${KEY_TARGET}:1 (raise "smoke"), ` +
                  `die needs ${DIE_TARGET}:1 (raise "wall").`);
    process.exit(1);
  }
})();
