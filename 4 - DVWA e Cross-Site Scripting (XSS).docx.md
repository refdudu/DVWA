Prof Tiago Mallmann Rohde   
tiago.rohde@unijui.edu.br   
**Segurança de Dados** 

**Ferramentas de testes de intrusão (pentest)** 

**Objetivo:** A atividade prática de execução de testes de intrusão com ferramentas especializadas tem como objetivo proporcionar aos estudantes uma experiência aplicada na identificação e exploração de vulnerabilidades em sistemas computacionais. Os estudantes deverão empregar ferramentas amplamente reconhecidas no campo da segurança ofensiva para realizar reconhecimento, análise de vulnerabilidades, exploração controlada e geração de relatórios técnicos. A atividade visa desenvolver competências relacionadas à avaliação de segurança, uso estratégico de ferramentas, elaboração de planos de ataque ético e tomada de decisão fundamentada em contextos de cibersegurança. Tais competências são essenciais para a atuação profissional em testes de segurança, auditorias técnicas e prevenção de riscos cibernéticos em ambientes corporativos. Diante disso, cada grupo deverá escolher um dos focos de pesquisa propostos para desenvolvimento da atividade. Caso o grupo deseje abordar uma temática diferente, a proposta poderá ser desenvolvida desde que previamente submetida e aprovada pelo professor. 

**DVWA e SQL Injection** 

A atividade será realizada em ambiente controlado utilizando a aplicação vulnerável Damn Vulnerable Web Application, uma plataforma amplamente utilizada para testes de segurança em aplicações web. O DVWA é uma aplicação deliberadamente insegura que implementa vulnerabilidades clássicas de segurança, incluindo SQL Injection, Cross-Site Scripting (XSS), Command Injection, entre outras. Seu objetivo é permitir a experimentação prática de técnicas de ataque e análise de vulnerabilidades em um ambiente isolado, sem risco para sistemas produtivos. Nesta atividade, o foco será exclusivamente em Cross-Site Scripting (XSS), com ênfase na compreensão  
de como falhas na validação e sanitização de entradas podem permitir a execução de código JavaScript malicioso no contexto do navegador da vítima. A análise deve evidenciar o impacto dessas falhas na integridade da interface, na manipulação de sessões e na exposição de informações do usuário. Referências para configuração e estudo inicial: 

● https://github.com/digininja/DVWA 

● https://www.edgenexus.io/pt-br/blog-pt-br/principais-recursos-do-d amn-vulnerable-web-app-dvwa/ 

Durante a execução, os estudantes deverão identificar pontos da aplicação suscetíveis a XSS e testar diferentes formas de inserção de payloads em campos de entrada, observando o comportamento da aplicação na resposta e no contexto de execução no navegador. A exploração deve ser realizada de forma controlada, com testes incrementais e análise cuidadosa dos efeitos produzidos no lado cliente. 

A análise deve ser conduzida de forma controlada, com exploração incremental e observação criteriosa das respostas do sistema, evitando automação massiva ou técnicas agressivas de exploração (ou seja, explorar sem ser detectado). Os resultados da atividade deverão ser documentados de forma técnica, incluindo evidências da exploração realizada, descrição dos comportamentos observados na aplicação, exemplos de entradas utilizadas e análise do impacto potencial da vulnerabilidade identificada. Espera-se que a documentação demonstre não apenas a execução da exploração, mas também a compreensão do risco associado e das implicações de segurança em cenários reais. 

A seguir, apresenta-se a estrutura mínima esperada para o relatório técnico da atividade. O documento deverá conter, **no máximo, 8 páginas de conteúdo**, além da capa, que deverá obrigatoriamente apresentar a identificação de todos os integrantes do grupo. Recomenda-se que o relatório seja elaborado de forma objetiva, técnica e organizada, priorizando clareza na  
apresentação das evidências, análises e resultados obtidos durante a execução da atividade. 

● **Introdução:** Contexto do teste de segurança em aplicação web vulnerável utilizando DVWA, com foco na exploração de Cross-Site Scripting (XSS) e sua relevância para compreensão de falhas de validação de entrada e execução de código no contexto do navegador. 

● **Objetivos da Análise:** Identificar pontos vulneráveis a XSS na aplicação, compreender o comportamento da interface diante de entradas maliciosas e avaliar o impacto potencial da execução de scripts no lado do cliente. 

● **Ferramentas Utilizadas:** DVWA como ambiente vulnerável de testes, navegador web, entre outras ferramentas utilizadas. 

● **Metodologia Aplicada:** Execução de testes manuais e controlados de XSS nos parâmetros da aplicação, com inserção de payloads e observação do comportamento no navegador, de forma incremental e orientada à análise de impacto. 

● **Resultados Obtidos:** Evidências de vulnerabilidades exploradas, payloads utilizados, comportamento da aplicação no cliente e efeitos observados decorrentes da execução de scripts. 

● **Análise de Segurança:** Interpretação das vulnerabilidades identificadas, avaliação do impacto do XSS e discussão sobre riscos associados à execução de código malicioso no contexto do navegador e da sessão do usuário. 

● **Conclusão:** Síntese dos achados da exploração, principais aprendizados sobre XSS e limitações de segurança observadas no ambiente DVWA. 

A apresentação dos trabalhos ocorrerá na 17ª aula da disciplina, havendo 10 minutos para a apresentação e 5 minutos para questionamentos, a avaliação será realizada com base nos critérios descritos a seguir:  
● **Qualidade técnica da atividade** (10 pontos): Coerência técnica, profundidade de análise e aderência conceitual aos temas abordados na disciplina. 

● **Organização e estruturação do relatório** (10 pontos): Clareza na organização das informações, consistência na apresentação dos resultados e fluidez estrutural do documento. 

● **Capacidade analítica e interpretativa** (10 pontos): Qualidade da leitura dos dados obtidos, interpretação dos resultados e articulação com aspectos de segurança da informação. 

● **Adequação metodológica e uso de ferramentas** (10 pontos): Pertinência das técnicas e ferramentas utilizadas, bem como aderência às restrições e diretrizes definidas para a atividade. 

● **Apresentação e defesa técnica** (10 pontos): Clareza na exposição oral, domínio do conteúdo desenvolvido e consistência nas respostas durante a arguição.