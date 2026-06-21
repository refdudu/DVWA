# Capa

UNIVERSIDADE REGIONAL DO NOROESTE DO ESTADO DO RIO GRANDE DO SUL (UNIJUÍ)

Curso: [PREENCHER]

Disciplina: Segurança de Dados

Atividade: Ferramentas de testes de intrusão (pentest)

DVWA e Cross-Site Scripting (XSS): exploração controlada e análise de segurança

Integrantes do grupo:

- [NOME COMPLETO e MATRÍCULA]
- [NOME COMPLETO e MATRÍCULA]
- [NOME COMPLETO e MATRÍCULA]

Professor: Tiago Mallmann Rohde

Ijuí, RS, 2026

<!-- QUEBRA DE PÁGINA APÓS A CAPA -->

# Introdução

O Cross-Site Scripting, conhecido pela sigla XSS, é uma das classes de vulnerabilidade mais persistentes no desenvolvimento de aplicações web. Ele ocorre quando uma aplicação incorpora dados controlados pelo usuário em uma página HTML sem o devido tratamento, permitindo que um atacante injete e execute código JavaScript arbitrário no contexto do navegador da vítima. As consequências vão do roubo de credenciais de sessão à manipulação completa da interface apresentada ao usuário, e por isso o XSS figura de forma recorrente entre os principais riscos catalogados pela OWASP.

Para conduzir este estudo de maneira controlada e ética, utilizamos o Damn Vulnerable Web Application (DVWA), uma aplicação propositadamente insegura, mantida para fins didáticos. O DVWA oferece quatro níveis de segurança (Low, Medium, High e Impossible) que permitem observar, de forma progressiva, como diferentes mecanismos de defesa alteram o comportamento de um mesmo ataque. Todo o ambiente foi executado localmente, em rede isolada, sem qualquer exposição a terceiros.

Este relatório documenta a exploração das três variantes clássicas de XSS suportadas pelo DVWA: a refletida (Reflected), a armazenada (Stored) e a baseada em DOM (DOM-based). Para cada variante foram testados três níveis de segurança, totalizando nove cenários, cada um acompanhado da evidência de execução do payload e da respectiva análise.

# Objetivos da Análise

O objetivo central deste trabalho é compreender, na prática, como vulnerabilidades de XSS se manifestam em uma aplicação web e como elas variam conforme o rigor das defesas aplicadas. Buscamos demonstrar empiricamente a execução de código JavaScript injetado em cada um dos três tipos de XSS, comparar o esforço necessário para contornar os filtros de cada nível de segurança e evidenciar o impacto concreto da falha por meio da leitura dos cookies acessíveis no navegador da vítima.

De forma complementar, pretende-se discutir as contramedidas que tornam o nível Impossible efetivamente resistente, relacionando cada técnica de defesa ao tipo de XSS que ela neutraliza. Com isso, o trabalho não se limita a reproduzir os ataques: busca também consolidar o entendimento das boas práticas de codificação segura.

# Ferramentas Utilizadas

A aplicação alvo foi o DVWA, executado em contêiner Docker e acessível no endereço local `http://localhost:4280`. Para a coleta sistemática das evidências, desenvolvemos um script de automação em Node.js apoiado na biblioteca Playwright, que controla uma instância do navegador Chromium. Essa abordagem garantiu reprodutibilidade: o script realiza o login na aplicação, ajusta o nível de segurança pelo cookie `security`, dispara cada um dos nove payloads e registra o resultado de forma uniforme. O guia operacional que acompanha esta atividade traz ainda os comandos `curl` equivalentes para reprodução manual.

Um aspecto técnico da automação merece destaque. A caixa de diálogo nativa gerada por `alert()` não aparece em capturas de tela convencionais, pois é renderizada pelo próprio navegador, fora do documento HTML. Para contornar isso, o script intercepta o evento `dialog` do Playwright, captura o texto exibido pelo alerta e injeta na página um banner com o payload utilizado, a URL acessada e o conteúdo retornado pelo alerta. A captura de tela resultante torna-se, assim, uma evidência autoexplicativa de que o código injetado de fato executou.

# Metodologia Aplicada

A análise seguiu um procedimento padronizado para os nove cenários. Em todos eles, o payload escolhido foi uma chamada a `alert(document.cookie)`, uma decisão metodológica deliberada: ao exibir o conteúdo dos cookies acessíveis dentro do alerta, demonstra-se que o script injetado opera no mesmo contexto de origem da aplicação e consegue ler dados do cliente. A presença desse conteúdo na mensagem capturada confirma a execução real do código, e não apenas a renderização do texto.

Para o XSS refletido, cada payload foi inserido no parâmetro GET `name` da página `xss_r`, de modo que a resposta do servidor refletisse o conteúdo injetado diretamente no HTML. No XSS armazenado, recorremos ao livro de visitas (`xss_s`). Aqui o envio foi feito por requisição POST direta, o que traz uma consequência importante: ignora a restrição de `maxlength`, imposta apenas no lado do cliente. O guestbook foi limpo antes de cada cenário, evitando contaminação entre os testes. Já no XSS baseado em DOM, o payload foi colocado no parâmetro `default` da página `xss_d`, cujo tratamento ocorre inteiramente no navegador.

Um detalhe de codificação foi decisivo nos testes de DOM. A URL foi construída com `encodeURI` em vez de `encodeURIComponent`, porque o sink vulnerável do DVWA aplica `decodeURI()` sobre o valor lido de `location.href`. Como `decodeURI` reverte sequências como `%3C` de volta para `<`, manter os caracteres estruturais legíveis foi necessário para que a injeção fosse reconstruída no DOM. No nível High dessa categoria, o payload foi transportado no fragmento da URL, depois do caractere `#`, parte que sequer trafega até o servidor e que, por isso, escapa de qualquer filtragem feita no lado servidor.

# Resultados Obtidos

Nos nove cenários executados, o alerta foi disparado com sucesso e exibiu o conteúdo de `document.cookie`, o que confirma a execução do código injetado em todos os níveis testados de cada categoria.

No XSS refletido, o nível Low não aplica nenhum tratamento, de modo que o payload mais direto, `<script>alert(document.cookie)</script>`, executa sem resistência. O nível Medium introduz uma remoção ingênua da tag `<script>`, contornada com um vetor que não depende dela: `<img src=x onerror=alert(document.cookie)>`. O nível High emprega uma filtragem mais agressiva, por expressão regular, contra variações de `<script>`, mas continua vulnerável a outros elementos capazes de carregar manipuladores de evento, como em `<svg/onload=alert(document.cookie)>`.

[PRINT 1]

No XSS armazenado, o nível Low novamente aceita `<script>alert(document.cookie)</script>` sem sanitização, persistido no campo de mensagem do livro de visitas e executado a cada visualização da página. No nível Medium, o filtro recai sobre o campo de mensagem, mas o campo de nome permanece vulnerável; aproveitando o envio por POST, que ignora o `maxlength`, foi possível armazenar `<img src=x onerror=alert(document.cookie)>` no campo de nome. No nível High, com a filtragem reforçada contra a tag de script, o vetor `<svg/onload=alert(document.cookie)>` foi armazenado e executado a partir do mesmo campo.

[PRINT 2]

No XSS baseado em DOM, o nível Low processa o parâmetro sem qualquer verificação, permitindo `<script>alert(document.cookie)</script>`. O nível Medium tenta bloquear a tag de script no lado servidor, o que foi contornado quebrando a estrutura do elemento `<select>` existente e injetando uma imagem com manipulador de erro, por meio de `</option></select><img src=x onerror=alert(document.cookie)>`. O nível High restringe os valores aceitos a um conjunto de idiomas conhecidos; a solução foi usar um valor legítimo seguido do payload no fragmento, como em `English#<script>alert(document.cookie)</script>`, explorando o fato de que o conteúdo após o `#` é lido pelo JavaScript no cliente sem trafegar ao servidor.

[PRINT 3]

O trecho a seguir ilustra o padrão do sink vulnerável de DOM, no qual o valor lido da URL é decodificado e escrito diretamente no documento, sem qualquer sanitização:

```javascript
var lang = location.href.substring(location.href.indexOf("default=") + 8);
document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
```

# Análise de Segurança

Os resultados confirmam a natureza progressiva das defesas no DVWA. O nível Low não oferece proteção alguma e serve apenas como linha de base. O nível Medium adota filtros por correspondência de padrões, tipicamente a remoção da string `<script>`, uma abordagem de lista de bloqueio que se mostra frágil, já que o vocabulário do HTML oferece inúmeros vetores alternativos, como atributos de evento em `<img>` e `<svg>`. O nível High endurece esses filtros, mas permanece na mesma lógica de bloqueio por padrões e, por isso, continua contornável.

Um achado empírico merece atenção. Embora o `alert(document.cookie)` confirme a execução do script nos nove cenários, o identificador de sessão `PHPSESSID` não apareceu no valor lido. A inspeção dos cabeçalhos `Set-Cookie` mostrou que a aplicação define o `PHPSESSID` com os atributos `HttpOnly` e `SameSite=Strict`, o que o torna inacessível ao JavaScript. Esse resultado evidencia o `HttpOnly` como uma camada de defesa em profundidade: o XSS executa, mas o roubo direto do cookie de sessão pela via `document.cookie` fica bloqueado. A exfiltração de sessão continua possível em aplicações que não adotam essa proteção, e outros impactos, como keylogging, alteração da interface e ações forjadas no contexto autenticado, independem da leitura do cookie e permanecem viáveis. Vale notar que essas flags reduzem o impacto, mas não corrigem a injeção em si.

O nível Impossible é o único efetivamente resistente, e isso decorre do uso combinado de técnicas corretas. No XSS refletido e no armazenado, a aplicação passa a tratar a saída com codificação de entidades HTML, de modo que caracteres como `<` e `>` deixam de ser interpretados como marcação. No caso específico do DOM, a defesa decisiva está na remoção do `decodeURI()`: sem essa decodificação, as sequências percent-encoded permanecem inertes (o `%3C` não volta a ser `<`) e o navegador não reconstrói a injeção, o que neutraliza o vetor na origem. Esse contraste explica de forma direta por que os níveis inferiores eram exploráveis e o Impossible não é.

De modo geral, a lição central é que a filtragem por lista de bloqueio é insuficiente. A defesa robusta contra XSS apoia-se na codificação contextual da saída, no uso de uma Content Security Policy adequada, na adoção de APIs seguras de manipulação do DOM (como Trusted Types) e na configuração defensiva dos cookies de sessão.

# Conclusão

A análise demonstrou, em todos os nove cenários, que as três variantes de XSS presentes no DVWA são exploráveis nos níveis Low, Medium e High, ainda que com esforço crescente de evasão dos filtros. A leitura de `document.cookie` em cada execução evidenciou de forma tangível que o código injetado acessa dados do cliente. Ao mesmo tempo, o `PHPSESSID` protegido por `HttpOnly` e `SameSite=Strict` não foi exposto, o que mostra o papel dessas configurações como defesa em profundidade.

Ficou claro que defesas baseadas em remoção de padrões oferecem uma falsa sensação de segurança, pois o atacante dispõe de múltiplos vetores alternativos. A resistência observada apenas no nível Impossible reforça que a mitigação eficaz exige codificação contextual da saída e a eliminação de operações inseguras de decodificação, como o `decodeURI()` no fluxo de DOM. O trabalho cumpriu seus objetivos ao reproduzir os ataques, registrar evidências reprodutíveis e relacionar cada técnica de defesa ao comportamento observado.

# Referências

- OWASP Foundation. Cross-Site Scripting (XSS). OWASP Community Pages. Disponível em: https://owasp.org/www-community/attacks/xss/
- OWASP Foundation. Cross-Site Scripting Prevention Cheat Sheet. OWASP Cheat Sheet Series. Disponível em: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP Foundation. DOM based XSS Prevention Cheat Sheet. OWASP Cheat Sheet Series. Disponível em: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- DVWA: Damn Vulnerable Web Application. Disponível em: https://github.com/digininja/DVWA
- Mozilla Developer Network (MDN). Set-Cookie. Disponível em: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
