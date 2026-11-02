// Tela "Sobre": o que é o EIGAN, como decide sem IA, fontes de dados e encerramento.

import { api } from "../api.js";
import { append, button, clear, confirmDialog, dateOnly, h } from "../ui.js";

export async function renderAbout(main, state) {
  const info = state.info || (await api("/api/info"));
  const kev = info.kev_catalog || {};
  const shutdown = button("Encerrar o EIGAN", {
    kind: "danger",
    iconName: "power",
    onClick: async () => {
      const running = info.running ? " As auditorias em andamento serão canceladas." : "";
      const ok = await confirmDialog({ title: "Encerrar o EIGAN?", text: `O painel deixa de funcionar até você abrir o EIGAN de novo.${running}`, confirmLabel: "Encerrar", danger: true });
      if (!ok) return;
      try {
        await api("/api/encerrar", { method: "POST" });
      } catch {
        /* o servidor pode fechar antes de responder */
      }
      clear(main).append(h("div", { class: "empty" }, h("p", { class: "empty-title", text: "EIGAN encerrado" }), h("p", { class: "empty-text", text: "Pode fechar esta aba. Para usar de novo, abra o EIGAN." })));
    },
  });
  append(main, [
    h("header", { class: "page-head" }, h("h1", { text: "Sobre o EIGAN" }), h("p", { class: "lead", text: `Versão ${info.version}, em desenvolvimento. ${info.tagline}.` })),
    h(
      "div",
      { class: "about" },
      h(
        "section",
        { class: "prose" },
        h("h2", { text: "Para que serve" }),
        h("p", { text: "O EIGAN é um auditor de segurança para quem defende: encontra vulnerabilidades e configurações fracas em sites, servidores, redes, na própria máquina, em código e em logs, e explica cada problema em português, com risco, passo a passo e exemplo de correção." }),
        h("h2", { text: "Como ele decide, sem IA" }),
        h("p", { text: "Um motor de regras encadeadas: cada descoberta vira um fato (\"este endereço responde HTTPS\", \"há um nginx 1.18\") e cada fato dispara as verificações que fazem sentido para ele. A prioridade, a nota, os cenários de risco e o plano de correção saem de regras transparentes e auditáveis. Nada é enviado para fora desta máquina e nenhuma chave de API é usada." }),
        h("h2", { text: "Uso responsável" }),
        h("p", { text: "Audite somente sistemas seus ou com autorização por escrito. As verificações são não intrusivas: leem o que um visitante comum veria, sem explorar falhas nem testar senhas." }),
        h("h2", { text: "Fontes de dados embarcadas" }),
        h(
          "ul",
          {},
          h("li", { text: `Catálogo CISA KEV (vulnerabilidades exploradas ativamente)${kev.publicado ? `, publicado em ${dateOnly(kev.publicado)}` : ""}.` }),
          h("li", { text: "Mapeamentos OWASP Top 10 (2021), CIS Controls v8, CWE e LGPD." }),
          h("li", { text: "Assinaturas e faixas de versão próprias, com referência pública em cada item da base." }),
        ),
      ),
      h(
        "aside",
        { class: "side-col" },
        h("h2", { class: "section-title", text: "Esta instalação" }),
        h(
          "dl",
          { class: "kv" },
          h("div", {}, h("dt", { text: "Versão" }), h("dd", { text: info.version })),
          h("div", {}, h("dt", { text: "Sistema" }), h("dd", { text: info.platform })),
          h("div", {}, h("dt", { text: "Verificações" }), h("dd", { text: String(info.checks) })),
          h("div", {}, h("dt", { text: "Tipos de problema" }), h("dd", { text: String(info.kb_entries) })),
          h("div", {}, h("dt", { text: "Dados" }), h("dd", { class: "break", text: info.data_dir })),
        ),
        h("div", { class: "stack" }, shutdown),
      ),
    ),
  ]);
  return null;
}
