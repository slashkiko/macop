// SVG -> PNG using the local Chromium.
//   node raster.js <svg> <out.png> <width> [height] [background] [ink]
//   node raster.js --batch <jobs.json>     // [[svg,out,w,h,bg,ink], ...] in one browser
const { chromium } = require('playwright');
const fs = require('fs');

async function shoot(page, [svgPath, out, w, h, bg, ink]) {
  const svg = fs.readFileSync(svgPath, 'utf8');
  const vb = svg.match(/viewBox="([\d.\-\s]+)"/)[1].trim().split(/\s+/).map(Number);
  const W = Math.round(+w);
  const H = Math.round(h && +h ? +h : W * (vb[3] / vb[2]));
  await page.setViewportSize({ width: W, height: H });
  await page.setContent(
    `<style>html,body{margin:0;padding:0;background:${bg || 'transparent'};color:${ink || '#161A24'}}
     svg{display:block;width:${W}px;height:${H}px}</style>` + svg);
  await page.screenshot({ path: out, omitBackground: !bg });
  return out;
}

(async () => {
  const a = process.argv.slice(2);
  const jobs = a[0] === '--batch' ? JSON.parse(fs.readFileSync(a[1], 'utf8')) : [a];
  const browser = await chromium.launch();
  const page = await browser.newPage({ deviceScaleFactor: 1 });
  for (const j of jobs) console.log('  ' + (await shoot(page, j)));
  await browser.close();
})();
