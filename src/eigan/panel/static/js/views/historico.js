// Telas "Histórico" e "Comparação" entre duas auditorias do mesmo alvo.

import { api } from "../api.js";
import { KIND, PROFILE, SEVERITY, append, button, clear, confirmDialog, dateTime, emptyState, gradeBadge, h, icon, plural, sevChip, toast } from "../ui.js";

export async function renderHistory(main) {
  const { scans } = await api("/api/historico?limite=500");
  const selected = new Set();
  const compareBtn = button("Comparar selecionadas", { kind: "secondary", iconName: "swap", attrs: { disabled: true } });
  const hint = h("p", { class: "muted", text: "Marque duas auditorias do mesmo alvo para comparar." });

  append(main, [
    h("header", { class: "page-head with-actions" }, h("div", {}, h("h1", { text: "Histórico" }), h("p", { class: "lead", text: "Todas as auditorias ficam salvas nesta máquina. Abra um resultado, compare a evolução de um alvo ou exclua o que não precisa mais." })), h("div", { class: "head-actions" }, compareBtn)),
  ]);
  if (!scans.length) {
    main.append(emptyState("Nenhuma auditoria ainda", "Faça a primeira auditoria para acompanhar a evolução da segurança aqui.", h("a", { class: "btn btn-primary", href: "#/nova" }, icon("plus", 16), h("span", { text: "Nova auditoria" }))));
    return null;
  }
  main.append(hint);

  const byTarget = new Map();
  for (const scan of scans) {
    if (!byTarget.has(scan.target_key)) byTarget.set(scan.target_key, []);
    byTarget.get(scan.target_key).push(scan);
  }

  const refreshCompare = () => {
    const picked = scans.filter((s) => selected.has(s.id));
    const sameTarget = picked.length === 2 && picked[0].target_key === picked[1].target_key;
    compareBtn.disabled = !sameTarget;
    hint.textContent = picked.length === 2 && !sameTarget ? "As duas auditorias precisam ser do mesmo alvo." : "Marque duas auditorias do mesmo alvo para comparar.";
  };
  compareBtn.addEventListener("click", () => {
    const [a, b] = scans.filter((s) => selected.has(s.id)).sort((x, y) => x.started_at.localeCompare(y.started_at));
    location.hash = `#/comparar/${a.id}/${b.id}`;
  });

  for (const [, group] of byTarget) {
    const latest = group[0];
    const section = h("section", { class: "history-group", "aria-label": latest.target });
    const rows = h("tbody");
    for (const scan of group) {
      const check = h("input", { type: "checkbox", "aria-label": `Selecionar auditoria de ${dateTime(scan.started_at)}` });
      check.addEventListener("change", () => {
        if (check.checked) selected.add(scan.id);
        else selected.delete(scan.id);
        refreshCompare();
      });
      const counts = ["critical", "high", "medium", "low"].filter((s) => scan[s]).map((s) => sevChip(s, `${scan[s]}`));
      const row = h(
        "tr",
        {},
        h("td", { class: "col-check" }, check),
        h("td", {}, h("a", { href: `#/resultado/${scan.id}`, text: dateTime(scan.started_at) })),
        h("td", {}, gradeBadge(scan.grade, scan.score), scan.score !== null ? h("span", { class: "score-num", text: ` ${scan.score}` }) : null),
        h("td", {}, counts.length ? h("span", { class: "chips-inline" }, counts) : h("span", { class: "muted", text: "Nenhum" })),
        h("td", { text: PROFILE[scan.profile] || scan.profile }),
        h("td", { text: scan.status === "cancelada" ? "Parcial" : "Concluída" }),
        h(
          "td",
          { class: "col-actions" },
          button("", {
            kind: "icon",
            iconName: "trash",
            attrs: { "aria-label": `Excluir auditoria de ${dateTime(scan.started_at)}`, title: "Excluir" },
            onClick: async () => {
              const ok = await confirmDialog({ title: "Excluir esta auditoria?", text: `${latest.target}, ${dateTime(scan.started_at)}. Os relatórios já salvos em pasta não são apagados.`, confirmLabel: "Excluir", danger: true });
              if (!ok) return;
              try {
                await api(`/api/resultados/${scan.id}`, { method: "DELETE" });
                selected.delete(scan.id);
                row.remove();
                toast("Auditoria excluída.", { kind: "ok" });
                refreshCompare();
              } catch (error) {
                toast(error.message, { kind: "error" });
              }
            },
          }),
        ),
      );
      rows.append(row);
    }
    append(section, [
      h(
        "div",
        { class: "history-head" },
        h("div", {}, h("h2", { class: "history-target break", text: latest.target }), h("p", { class: "muted", text: `${KIND[latest.kind] || latest.kind} · ${plural(group.length, "auditoria", "auditorias")}` })),
        trend(group),
      ),
      h(
        "div",
        { class: "table-wrap" },
        h("table", { class: "table" }, h("thead", {}, h("tr", {}, h("th", { scope: "col", class: "col-check" }, h("span", { class: "visually-hidden", text: "Selecionar" })), ["Data", "Nota", "Achados abertos", "Perfil", "Situação"].map((t) => h("th", { scope: "col", text: t })), h("th", { scope: "col" }, h("span", { class: "visually-hidden", text: "Ações" })))), rows),
      ),
    ]);
    main.append(section);
  }
  return null;
}

function trend(group) {
  const points = group.filter((s) => typeof s.score === "number").slice(0, 12).reverse();
  if (points.length < 2) return null;
  const w = 160;
  const hgt = 40;
  const step = w / (points.length - 1);
  const coords = points.map((p, i) => `${(i * step).toFixed(1)},${(hgt - (p.score / 100) * (hgt - 4) - 2).toFixed(1)}`);
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${hgt}`);
  svg.setAttribute("width", w);
  svg.setAttribute("height", hgt);
  svg.setAttribute("class", "trend");
  svg.setAttribute("role", "img");
  const first = points[0].score;
  const last = points[points.length - 1].score;
  svg.setAttribute("aria-label", `Evolução da nota: de ${first} para ${last}`);
  const line = document.createElementNS(ns, "polyline");
  line.setAttribute("points", coords.join(" "));
  line.setAttribute("fill", "none");
  line.setAttribute("stroke", "currentColor");
  line.setAttribute("stroke-width", "2");
  line.setAttribute("stroke-linejoin", "round");
  svg.append(line);
  const [lx, ly] = coords[coords.length - 1].split(",");
  const dot = document.createElementNS(ns, "circle");
  dot.setAttribute("cx", lx);
  dot.setAttribute("cy", ly);
  dot.setAttribute("r", "3");
  dot.setAttribute("fill", "currentColor");
  svg.append(dot);
  return h("div", { class: "trend-box", title: `Nota: ${points.map((p) => p.score).join(", ")}` }, svg, h("span", { class: "muted", text: `${first} para ${last}` }));
}

export async function renderCompare(main, oldId, newId) {
  const d = await api(`/api/comparar?a=${encodeURIComponent(oldId)}&b=${encodeURIComponent(newId)}`);
  const delta = d.delta > 0 ? `+${d.delta}` : String(d.delta);
  const block = (title, items, hint) =>
    h(
      "section",
      { class: "compare-block" },
      h("h2", { class: "section-title" }, title, h("span", { class: "tab-count", text: String(items.length) })),
      hint ? h("p", { class: "section-hint", text: hint }) : null,
      items.length
        ? h("ul", { class: "compare-list" }, items.map((i) => h("li", {}, sevChip(i.severity), h("div", {}, h("p", { text: i.title }), h("p", { class: "muted break", text: i.asset })))))
        : h("p", { class: "muted", text: "Nenhum." }),
    );
  append(main, [
    h(
      "header",
      { class: "page-head" },
      h("p", { class: "crumbs" }, h("a", { href: "#/historico", text: "Histórico" }), h("span", { "aria-hidden": "true", text: " / " }), h("span", { text: "Comparação" })),
      h("h1", { class: "break", text: d.target }),
      h("p", { class: "lead" }, `${dateTime(d.previous_date)} comparada com ${dateTime(d.current_date)}`),
    ),
    h(
      "section",
      { class: "compare-score surface" },
      h("div", {}, h("p", { class: "muted", text: "Antes" }), gradeBadge(d.grade_before, d.score_before), h("strong", { class: "score-big", text: ` ${d.score_before}` })),
      h("div", {}, h("p", { class: "muted", text: "Depois" }), gradeBadge(d.grade_after, d.score_after), h("strong", { class: "score-big", text: ` ${d.score_after}` })),
      h("div", {}, h("p", { class: "muted", text: "Variação" }), h("strong", { class: `score-big ${d.delta > 0 ? "up" : d.delta < 0 ? "down" : ""}`, text: delta })),
      h("div", { class: "compare-links" }, h("a", { href: `#/resultado/${d.previous_id}`, text: "Abrir a anterior" }), h("a", { href: `#/resultado/${d.current_id}`, text: "Abrir a atual" })),
    ),
    h(
      "div",
      { class: "compare-grid" },
      block("Corrigidos", d.fixed, "A verificação rodou de novo e o problema não apareceu."),
      block("Novos", d.new, null),
      block("Ainda abertos", d.persisting, null),
      d.unverified.length ? block("Não verificados", d.unverified, "A verificação que encontrou estes problemas não rodou na auditoria mais recente (perfil mais leve ou erro). Não conte como corrigidos.") : null,
    ),
  ]);
  return null;
}

export { SEVERITY };
