/**
 * Gera o relatorio em .docx a partir do markdown, via pandoc.
 * Insere uma quebra de pagina real (OpenXML) no lugar do comentario
 * <!-- QUEBRA DE PÁGINA APÓS A CAPA --> para a capa ficar isolada.
 *
 * Uso: node make-docx.js
 * Requer pandoc no PATH.
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const SRC = path.join('C:', 'www', 'DVWA', 'relatorio-xss-dvwa.md');
const OUT = path.join('C:', 'www', 'DVWA', 'relatorio-xss-dvwa.docx');
const TMP = path.join(__dirname, '_build_relatorio.md');

const pageBreak = '\n```{=openxml}\n<w:p><w:r><w:br w:type="page"/></w:r></w:p>\n```\n';

let md = fs.readFileSync(SRC, 'utf8');
md = md.replace('<!-- QUEBRA DE PÁGINA APÓS A CAPA -->', pageBreak);
fs.writeFileSync(TMP, md, 'utf8');

try {
  execFileSync('pandoc', [TMP, '-o', OUT, '--from', 'gfm+raw_attribute', '--to', 'docx'], { stdio: 'inherit' });
  console.log('docx gerado: ' + OUT);
} finally {
  if (fs.existsSync(TMP)) fs.unlinkSync(TMP);
}
