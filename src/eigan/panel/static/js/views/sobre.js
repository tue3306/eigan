// Tela "Sobre": o que é o EIGAN, como decide sem IA, fontes de dados e encerramento.

import { api } from "../api.js";
import { append, button, clear, confirmDialog, dateOnly, h, icon, plural, toast } from "../ui.js";

// Seção "Dados e catálogos": idade de cada catálogo e o botão que baixa os mais novos.
// A atualização só acontece quando o usuário clica; a auditoria nunca baixa nada.
function catalogsSection(initial) {
  const box = h("div", { id: "catalogos" });

  function row(c) {
    const age = c.idade_dias === null || c.idade_dias === undefined ? "—" : plural(c.idade_dias, "dia", "dias");
    const stale = c.atualizavel && c.idade_dias !== null && c.idade_dias > (box.limit || 30);
    return h(
      "tr",
      {},
      h("td", { text: c.titulo }),
      h("td", { text: c.versao ? String(c.versao).split(" (")[0] : "—", title: c.versao || "" }),
      h("td", { text: c.data ? dateOnly(c.data) : "—" }),
      h("td", { class: stale ? "kev-note" : "", text: age }),
      h("td", { text: c.atualizavel ? (c.origem === "baixado" ? "Baixado" : "Embarcado") : "Curadoria manual" }),
    );
  }

  function draw(data) {
    box.limit = data.limite_dias;
    const busy = { value: false };
    const update = button("Atualizar catálogos", {
      kind: "primary",
      iconName: "refresh",
      onClick: async () => {
        if (busy.value) return;
        busy.value = true;
        update.disabled = true;
        update.lastChild.textContent = "Baixando…";
        try {
          const result = await api("/api/catalogos/atualizar", { method: "POST", body: {} });
          const failed = result.resultados.filter((r) => !r.ok);
          if (failed.length) toast(`${failed.map((r) => `${r.nome}: ${r.erro}`).join(" · ")}. Os dados anteriores foram mantidos.`, { kind: "error", timeout: 9000 });
          else {
            const kept = result.resultados.filter((r) => !r.gravado);
            if (!kept.length) toast("Catálogos atualizados.", { kind: "ok" });
            else {
              const reasons = kept.map((r) => `${r.nome}: ${r.motivo || "sem alterações"}`).join(" · ");
              const some = kept.length < result.resultados.length;
              toast(some ? `Atualizados os demais. Sem alterações: ${reasons}.` : `Nada foi atualizado. ${reasons}.`, { kind: some ? "ok" : "info", timeout: 9000 });
            }
          }
          draw(result);
        } catch (err) {
          toast(err.message, { kind: "error", timeout: 9000 });
          busy.value = false;
          update.disabled = false;
          update.lastChild.textContent = "Atualizar catálogos";
        }
      },
    });
    clear(box);
    append(box, [
      h("h2", { text: "Dados e catálogos" }),
      h("p", { text: "As verificações usam catálogos que vão dentro do EIGAN. Você pode baixar versões mais novas dos três que têm fonte pública; o EIGAN só acessa a Internet quando você clica no botão ou roda eigan atualizar." }),
      (data.avisos || []).map((text) => h("div", { class: "notice notice-warn", role: "status" }, icon("alert", 18), h("p", { text }))),
      h(
        "div",
        { class: "table-wrap" },
        h(
          "table",
          { class: "table" },
          h("thead", {}, h("tr", {}, ["Catálogo", "Versão", "Data", "Idade", "Origem"].map((t) => h("th", { text: t })))),
          h("tbody", {}, data.catalogos.map(row)),
        ),
      ),
      h("div", { class: "stack" }, update),
    ]);
  }

  draw(initial);
  return box;
}

export async function renderAbout(main, state) {
  const info = state.info || (await api("/api/info"));
  const catalogs = await api("/api/catalogos").catch(() => info.catalogos);
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
          h("li", { text: "Catálogo CISA KEV (vulnerabilidades exploradas ativamente), retire.js e lista de sufixos públicos, atualizáveis abaixo." }),
          h("li", { text: "Mapeamentos OWASP Top 10 (2021), CIS Controls v8, CWE e LGPD." }),
          h("li", { text: "Assinaturas e faixas de versão próprias, com referência pública em cada item da base." }),
        ),
        catalogs ? catalogsSection(catalogs) : null,
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
