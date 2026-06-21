# DVWA XSS — Captura automatizada de evidências

Script Playwright que loga no DVWA, executa os 9 cenários de XSS (Reflected / Stored / DOM × Low / Medium / High), captura o `alert(document.cookie)` de cada um e gera **3 prints compostos** prontos para o relatório.

## Pré-requisitos

- DVWA rodando (Docker): `http://localhost:4280`
- Node.js 18+

## Instalação

```powershell
cd C:\www\DVWA\xss-evidence
npm install
npx playwright install chromium
```

## Uso

```powershell
# Captura tudo (assume banco já criado e login admin/password)
npm run capture

# Se o login falhar (banco não criado), rode uma vez com setup:
npm run setup
```

Variáveis de ambiente opcionais:

```powershell
$env:DVWA_URL  = "http://localhost:4280"   # alvo
$env:DVWA_USER = "admin"
$env:DVWA_PASS = "password"
$env:HEADED    = "1"                        # abre o navegador visível (debug)
npm run capture
```

## Saída — pasta `output/`

| Arquivo | Conteúdo |
|---|---|
| `shot_reflected_low.png` … `shot_dom_high.png` | 9 capturas individuais (página + banner-evidência com payload, URL e cookie). |
| `PRINT_1_reflected.png` | **Composto** Reflected (Low/Medium/High). → relatório seção *Resultados Obtidos*. |
| `PRINT_2_stored.png` | **Composto** Stored (Low/Medium/High). |
| `PRINT_3_dom.png` | **Composto** DOM (Low/Medium/High). |
| `results.json` | Log: payload, URL, se o `alert` disparou e a mensagem capturada. |

Use `PRINT_1`, `PRINT_2` e `PRINT_3` nos marcadores `[PRINT 1/2/3]` do `relatorio-xss-dvwa.md`.

## Como funciona

- **Alert nativo não entra em screenshot.** O script captura a mensagem via evento `dialog` do Playwright, depois injeta um banner verde na página com o payload, a URL e o cookie capturado — e tira o print disso (evidência auto-explicativa).
- **DOM:** a URL usa `encodeURI` (preserva `/`), pois o sink do DVWA aplica `decodeURI()` no valor lido de `location.href`. O nível High usa o fragmento `#`, que não trafega ao servidor.
- **Stored:** o payload é enviado por POST direto (Playwright `request`), o que **ignora o `maxlength`** client-side dos campos. O guestbook é limpo antes de cada cenário.

## Aviso

Uso restrito a este laboratório DVWA local, isolado (`127.0.0.1`) e autorizado. Não utilizar contra sistemas de terceiros.
