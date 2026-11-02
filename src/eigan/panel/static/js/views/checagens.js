// Tela "Verificações": o que o EIGAN verifica e a base de conhecimento de correções.

import { api } from "../api.js";
import { PROFILE, SEVERITY, append, clear, emptyState, externalLink, h, icon, plural, sevChip } from "../ui.js";

const CATEGORY = { web: "Web", tls: "TLS e certificados", dns: "DNS e e-mail", rede: "Rede e serviços", host: "Sistema operacional", codigo: "Código e dependências", logs: "Logs" };

export async function renderChecks(main) {
  const data = await api("/api/checagens");
  const state = { text: "", category: "", entry: null };
  const search = h("input", { type: "search", class: "input", placeholder: "Buscar: HSTS, SMB, segredo, DMARC…", "aria-label": "Buscar verificações e problemas" });
  const catSel = h("select", { class: "input input-sm", "aria-label": "Categoria" }, h("option", { value: "", text: "Todas as categorias" }), Object.entries(CATEGORY).map(([v, l]) => h("option", { value: v, text: l })));
  const list = h("div", { class: "kb-list" });
  const detail = h("aside", { class: "kb-detail", "aria-live": "polite" });

  const drawDetail = async (id) => {
    clear(detail).append(h("p", { class: "muted", text: "Carregando…" }));
    let entry;
    try {
      entry = await api(`/api/kb/${encodeURIComponent(id)}`);
    } catch (error) {
      clear(detail).append(h("p", { class: "form-error", text: error.message }));
      return;
    }
    clear(detail);
    const tags = [entry.cwe, entry.owasp, ...(entry.cis || []).map((c) => `CIS ${c}`), entry.lgpd ? "LGPD" : null].filter(Boolean);
    append(detail, [
      h("p", { class: "kb-id" }, h("code", { text: entry.id })),
      h("h2", { class: "kb-title" }, sevChip(entry.severity), h("span", { text: entry.title })),
      h("p", { class: "lead", text: entry.summary }),
      h("h3", { text: "O que é" }),
      h("p", { text: entry.explanation }),
      h("h3", { text: "Risco" }),
      h("p", { text: entry.risk }),
      h("h3", { text: "Como corrigir" }),
      h("ol", { class: "steps" }, entry.steps.map((s) => h("li", { text: s }))),
      (entry.examples || []).map((fx) => h("div", { class: "kb-example" }, h("p", { class: "fixes-title", text: fx.label }), h("div", { class: "code" }, h("pre", {}, h("code", { text: fx.code }))))),
      entry.verify ? [h("h3", { text: "Como verificar" }), h("p", { text: entry.verify })] : null,
      tags.length ? h("p", { class: "tags" }, tags.map((t) => h("span", { class: "chip chip-tag", text: t }))) : null,
      entry.references?.length ? [h("h3", { text: "Referências" }), h("ul", { class: "refs" }, entry.references.map((r) => h("li", {}, externalLink(r))))] : null,
    ]);
  };

  const drawList = () => {
    clear(list);
    const text = state.text.toLowerCase();
    const checks = data.checks.filter((c) => (!state.category || c.category === state.category) && (!text || `${c.id} ${c.name} ${c.description}`.toLowerCase().includes(text)));
    const entries = data.kb.filter((e) => (!state.category || e.category === state.category) && (!text || `${e.id} ${e.title} ${e.summary}`.toLowerCase().includes(text)));
    if (!checks.length && !entries.length) {
      list.append(emptyState("Nada encontrado", "Tente outro termo ou outra categoria."));
      return;
    }
    for (const [cat, label] of Object.entries(CATEGORY)) {
      const cChecks = checks.filter((c) => c.category === cat);
      const cEntries = entries.filter((e) => e.category === cat);
      if (!cChecks.length && !cEntries.length) continue;
      const group = h("section", { class: "kb-group" }, h("h2", { class: "section-title" }, label, h("span", { class: "tab-count", text: String(cEntries.length) })));
      if (cChecks.length) {
        group.append(
          h(
            "details",
            { class: "kb-checks" },
            h("summary", { text: `${plural(cChecks.length, "verificação", "verificações")} desta categoria` }),
            h("ul", {}, cChecks.map((c) => h("li", {}, h("strong", { text: c.name }), h("span", { class: "muted", text: ` · ${c.profiles.map((p) => PROFILE[p] || p).join(", ")}` }), h("p", { class: "muted", text: c.description })))),
          ),
        );
      }
      group.append(
        h(
          "ul",
          { class: "kb-entries" },
          cEntries.map((e) =>
            h(
              "li",
              {},
              h(
                "button",
                { type: "button", class: "kb-entry", "aria-pressed": state.entry === e.id ? "true" : "false", on: { click: () => { state.entry = e.id; drawList(); drawDetail(e.id); } } },
                sevChip(e.severity, SEVERITY[e.severity]),
                h("span", { class: "kb-entry-text" }, h("span", { class: "kb-entry-title", text: e.title }), h("span", { class: "muted", text: e.summary })),
                icon("chevron", 16),
              ),
            ),
          ),
        ),
      );
      list.append(group);
    }
  };

  search.addEventListener("input", () => {
    state.text = search.value;
    drawList();
  });
  catSel.addEventListener("change", () => {
    state.category = catSel.value;
    drawList();
  });

  append(main, [
    h(
      "header",
      { class: "page-head" },
      h("h1", { text: "Verificações" }),
      h("p", { class: "lead", text: `${plural(data.checks.length, "verificação automática", "verificações automáticas")} e ${plural(data.kb.length, "tipo de problema", "tipos de problema")} com explicação, risco e passo a passo de correção. Tudo funciona offline.` }),
    ),
    h("div", { class: "toolbar" }, search, catSel),
    h("div", { class: "kb-layout" }, list, detail),
  ]);
  detail.append(h("p", { class: "muted", text: "Escolha um problema na lista para ver a explicação e a correção." }));
  drawList();
  return null;
}
