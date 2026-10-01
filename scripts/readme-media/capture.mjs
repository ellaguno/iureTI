// Conduce la interfaz web REAL de iureTI Discovery servida por demo_server.py (datos ficticios)
// y produce los cuadros del GIF y las capturas del README.
//
//   DATA=/tmp/iureti-demo PORT=8766 node scripts/readme-media/capture.mjs
//
// Salida: $OUT (por omisión $DATA/cap): hero/NNN.png + hero.txt (lista concat de ffmpeg) y las
// capturas sueltas (scan.png, assets.png, detail.png, settings.png).
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

// puppeteer-core: `npm i --no-save puppeteer-core` aquí, o PUPPETEER_DIR=<carpeta con node_modules>
const req = createRequire(path.join(process.env.PUPPETEER_DIR || path.dirname(new URL(import.meta.url).pathname), 'x.js'));
const puppeteer = (await import(req.resolve('puppeteer-core'))).default;

const DATA = process.env.DATA;
const PORT = process.env.PORT || '8766';
const OUT = process.env.OUT || path.join(DATA, 'cap');
const CHROME = process.env.CHROME || process.env.HOME + '/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome';
const URL_ = `http://127.0.0.1:${PORT}/`;
fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(path.join(OUT, 'hero'), { recursive: true });

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const b = await puppeteer.launch({ executablePath: CHROME, args: ['--no-sandbox', '--font-render-hinting=none', '--lang=es-MX'] });

// ---- 1) Ilustraciones de producto (planas, hechas aquí; no son fotos de terceros) ----------------
const imgId = (name) => (Buffer.from(name).toString('hex') + '0'.repeat(20)).slice(0, 20); // = demo_server.img_id
const box = (x, y, w, h, fill, r = 8) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${r}" fill="${fill}"/>`;
const ports = (x, y, n, gap = 22, fill = '#1f2937', w = 16, h = 12) =>
  Array.from({ length: n }, (_, i) => `<rect x="${x + i * gap}" y="${y}" width="${w}" height="${h}" rx="2" fill="${fill}"/>`).join('');
const leds = (x, y, n, gap = 22, fill = '#22c55e') =>
  Array.from({ length: n }, (_, i) => `<circle cx="${x + i * gap}" cy="${y}" r="3" fill="${fill}"/>`).join('');
const ILLU = {
  firewall: box(20, 120, 360, 90, '#d1d5db', 10) + box(20, 120, 360, 22, '#b91c1c', 10) + box(20, 132, 360, 10, '#b91c1c', 0) +
    ports(120, 165, 10) + leds(128, 155, 10) + box(40, 160, 60, 22, '#9ca3af', 4),
  switch: box(10, 130, 380, 70, '#1e3a5f', 8) + ports(30, 145, 12, 24, '#0b1324') + ports(30, 170, 12, 24, '#0b1324') +
    leds(38, 141, 12, 24, '#4ade80') + box(330, 150, 44, 30, '#0b1324', 3),
  nas: box(110, 50, 180, 230, '#111827', 14) + [0, 1, 2, 3].map((i) => box(130 + i * 38, 80, 30, 150, '#374151', 4) + `<circle cx="${145 + i * 38}" cy="215" r="3" fill="#60a5fa"/>`).join('') +
    `<circle cx="200" cy="258" r="6" fill="#60a5fa"/>`,
  printer: box(70, 120, 260, 120, '#e5e7eb', 14) + box(100, 70, 200, 60, '#d1d5db', 8) + box(110, 225, 180, 30, '#f9fafb', 4) +
    box(250, 140, 60, 26, '#111827', 4) + `<circle cx="100" cy="150" r="5" fill="#22c55e"/>`,
  ap: `<ellipse cx="200" cy="170" rx="150" ry="150" fill="#f3f4f6"/><ellipse cx="200" cy="170" rx="150" ry="150" fill="none" stroke="#d1d5db" stroke-width="6"/>` +
    `<ellipse cx="200" cy="170" rx="70" ry="70" fill="none" stroke="#3b82f6" stroke-width="10" opacity=".85"/>`,
  ups: box(20, 120, 360, 90, '#111827', 10) + box(40, 140, 110, 50, '#1f2937', 4) + box(50, 150, 90, 30, '#38bdf8', 3) +
    leds(190, 165, 6, 20, '#22c55e') + ports(310, 155, 2, 30, '#374151', 20, 20),
};
{
  const p = await b.newPage();
  await p.setViewport({ width: 400, height: 340, deviceScaleFactor: 1 });
  for (const [name, body] of Object.entries(ILLU)) {
    await p.setContent(`<html><body style="margin:0;background:#fff"><svg width="400" height="340" viewBox="0 0 400 340">${body}</svg></body></html>`);
    await p.screenshot({ path: path.join(DATA, 'cache', 'images', imgId(name) + '.png') });
  }
  await p.close();
}

// ---- 2) La interfaz real ---------------------------------------------------------------------
const p = await b.newPage();
p.on('pageerror', (e) => console.log('ERR:', e.message));
p.on('console', (m) => m.type() === 'error' && console.log('console:', m.text()));
await p.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'light' }]);
await p.setViewport({ width: 1280, height: 800, deviceScaleFactor: 1.5 });
await p.goto(URL_, { waitUntil: 'networkidle0' });
await p.addStyleTag({ content: '*{caret-color:transparent!important;transition:none!important;animation:none!important} #toast{display:none!important} textarea,input{spellcheck:false}' });
await wait(500);

// GIF: cuadros con marca de tiempo
const frames = [];
let t0 = Date.now();
const frame = async (hold = 0) => {
  const n = frames.length;
  const file = `hero/${String(n).padStart(3, '0')}.png`;
  await p.screenshot({ path: path.join(OUT, file) });
  frames.push({ file, t: Date.now() - t0, hold });
};

// Escaneo: elegir las dos redes de la sonda (chips) y lanzar
await p.$eval('#targets', (e) => (e.value = ''));
await frame(700);
for (const chip of await p.$$('#networks .chip')) { await chip.click(); await wait(250); await frame(400); }
await p.click('#start-scan');
t0 = Date.now() - frames.at(-1).t - 450;
for (;;) {
  await frame();
  const running = await p.$eval('#cancel-scan', (e) => !e.disabled);
  if (!running && (await p.$eval('#scan-phase', (e) => e.textContent.includes('terminado')))) break;
  await wait(120);
}
await wait(400);
await frame(1300);
// Resultado: la lista de activos clasificados
await p.click('nav button[data-tab="assets"]');
await p.waitForSelector('#assets tr');
await wait(500);
await frame(1200);
await p.mouse.wheel({ deltaY: 300 });
await wait(300);
await frame(1600);
await p.mouse.wheel({ deltaY: -600 });
await wait(200);
// lista concat de ffmpeg: duración de cada cuadro = hasta el siguiente (o su "hold")
const lines = frames.map((f, i) => {
  const next = frames[i + 1];
  const dur = f.hold || (next ? Math.max(0.06, (next.t - f.t) / 1000) : 1.5) * 1000;
  return `file '${f.file}'\nduration ${(dur / 1000).toFixed(3)}`;
});
lines.push(`file '${frames.at(-1).file}'`);
fs.writeFileSync(path.join(OUT, 'hero.txt'), lines.join('\n') + '\n');

// ---- 3) Capturas sueltas -------------------------------------------------------------------
const shot = (name) => p.screenshot({ path: path.join(OUT, name) });

// Escaneo terminado (con historial)
await p.click('nav button[data-tab="scan"]');
await wait(300);
await shot('scan.png');

// Activos tras enviar a iurefficient (estados de la bandeja)
await p.click('nav button[data-tab="assets"]');
await p.click('#sync');
await wait(1200);
await p.evaluate(() => window.scrollTo(0, 0));
await shot('assets.png');

// Ficha de un activo identificado en internet (firewall: primera fila)
await p.click('#assets tr[data-id] .toggle');
await wait(800);
await p.evaluate(() => { const d = document.querySelector('#assets tr.detail'); window.scrollTo(0, d.getBoundingClientRect().top + window.scrollY - 230); });
await wait(300);
await shot('detail.png');

// Configuración (tema oscuro)
await p.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'dark' }]);
await p.click('nav button[data-tab="settings"]');
await p.evaluate(() => window.scrollTo(0, 0));
await wait(400);
await shot('settings.png');

await b.close();
console.log(`${frames.length} cuadros, capturas en ${OUT}`);
