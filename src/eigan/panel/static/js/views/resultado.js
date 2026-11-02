// Tela "Resultado": veredito, plano de correção, achados com triagem, cenários,
// pontos fortes, conformidade, inventário e linha do tempo.

import { api, reportUrl } from "../api.js";
import {
  CONFIDENCE,
  EXPOSURE,
  KIND,
  PROFILE,
  SEVERITY,
  SEVERITY_ORDER,
  TRIAGE,
  append,
  bandChip,
  button,
  clear,
  confirmDialog,
  copyText,
  dateTime,
  duration,
  emptyState,
  externalLink,
  gradeClass,
  h,
  icon,
  plural,
  sevChip,
  timeOnly,
  toast,
} from "../ui.js";

const TABS = [
  { id: "plano", label: "Plano de correção" },
  { id: "achados", label: "Achados" },
  { id: "cenarios", label: "Cenários de risco" },
  { id: "pontos-fortes", label: "Pontos fortes" },
  { id: "conformidade", label: "Conformidade" },
  { id: "inventario", label: "Inventário" },
  { id: "linha-do-tempo", label: "Linha do tempo" },
];

export async function renderResult(main, scanId, initialTab) {
  const view = {
    data: await api(`/api/resultados/${scanId}`),
    tab: TABS.some((t) => t.id === initialTab) ? initialTab : "plano",
    kb: new Map(),
    filters: { text: "", severities: new Set(), status: "abertos" },
    openFinding: null,
    openAction: null,
  };
  const root = h("div", { class: "result" });
  main.append(root);
  const draw = () => {
    const y = window.scrollY;
    clear(root);
    append(root, [header(view), verdict(view), diffBanner(view), tabsNav(view), h("div", { class: "tab-panel", id: "painel-aba" }, tabContent(view, draw))]);
    window.scrollTo(0, y);
  };
  view.redraw = draw;
  draw();
  const onTab = (event) => {
    view.tab = TABS.some((t) => t.id === event.detail) ? event.detail : "plano";
    const nav = root.querySelector(".tabs");
    nav?.replaceWith(tabsNav(view));
    const panel = root.querySelector("#painel-aba");
    clear(panel).append(tabContent(view, draw));
  };
  window.addEventListener("eigan:tab", onTab);
  return () => window.removeEventListener("eigan:tab", onTab);
}

// -- cabeçalho e veredito -------------------------------------------------------------------

function header(view) {
  const d = view.data;
  const statusNote = d.status === "cancelada" ? h("span", { class: "chip chip-warn", text: "Parcial: auditoria cancelada" }) : null;
  const exportMenu = h(
    "div",
    { class: "export" },
    h("a", { class: "btn btn-primary", href: reportUrl(d.id, "html"), target: "_blank", rel: "noopener" }, icon("file", 16), h("span", { text: "Abrir relatório" })),
    h(
      "details",
      { class: "menu" },
      h("summary", { class: "btn btn-secondary" }, icon("download", 16), h("span", { text: "Exportar" })),
      h(
        "div",
        { class: "menu-list", role: "menu" },
        [
          ["pdf", "PDF executivo"],
          ["html", "HTML completo"],
          ["json", "JSON (dados)"],
          ["sarif", "SARIF (GitHub, GitLab, Azure)"],
          ["csv", "CSV (planilha)"],
        ].map(([fmt, label]) => h("a", { class: "menu-item", role: "menuitem", href: reportUrl(d.id, fmt, true), download: "" }, label)),
        h("hr", {}),
        h(
          "button",
          {
            type: "button",
            class: "menu-item",
            role: "menuitem",
            on: {
              click: async (event) => {
                event.currentTarget.closest("details").open = false;
                try {
                  const res = await api(`/api/resultados/${d.id}/exportar`, { method: "POST", body: {} });
                  toast(`Relatórios salvos em ${res.pasta}`, {
                    kind: "ok",
                    timeout: 9000,
                    action: { label: "Abrir pasta", run: () => api("/api/abrir-pasta", { method: "POST", body: { pasta: res.pasta } }).catch((e) => toast(e.message, { kind: "error" })) },
                  });
                } catch (error) {
                  toast(error.message, { kind: "error" });
                }
              },
            },
          },
          "Salvar todos na pasta de relatórios",
        ),
      ),
    ),
    button("Auditar de novo", {
      kind: "secondary",
      iconName: "refresh",
      onClick: async () => {
        const ok = await confirmDialog({
          title: `Auditar ${d.target} de novo?`,
          text: `Mesmo tipo e perfil (${PROFILE[d.profile] || d.profile}). Confirme que a autorização para avaliar este alvo continua válida.`,
          confirmLabel: "Iniciar auditoria",
        });
        if (!ok) return;
        try {
          const { job } = await api("/api/auditorias", { method: "POST", body: { alvo: d.target, tipo: d.kind, perfil: d.profile, autorizado: true } });
          location.hash = `#/auditoria/${job.id}`;
        } catch (error) {
          toast(error.message, { kind: "error" });
        }
      },
    }),
  );
  return h(
    "header",
    { class: "page-head with-actions" },
    h(
      "div",
      { class: "head-text" },
      h("p", { class: "crumbs" }, h("a", { href: "#/historico", text: "Histórico" }), h("span", { "aria-hidden": "true", text: " / " }), h("span", { text: "Resultado" })),
      h("h1", { class: "break", text: d.target }),
      h("p", { class: "lead" }, `${KIND[d.kind] || d.kind} · perfil ${PROFILE[d.profile] || d.profile} · ${dateTime(d.started_at)} · ${duration(d.analysis?.stats?.duration ?? 0)} `, statusNote),
    ),
    h("div", { class: "head-actions" }, exportMenu),
  );
}

function verdict(view) {
  const a = view.data.analysis || {};
  const p = a.posture || {};
  const n = a.narrative || {};
  const c = a.counts || {};
  const evaluated = a.evaluated;
  const gradeBlock = h(
    "div",
    { class: `grade-block ${gradeClass(p.grade)}` },
    h("span", { class: "grade-letter", text: p.grade || "—" }),
    evaluated ? h("span", { class: "grade-score" }, h("strong", { text: String(p.score) }), "/100") : null,
    h("span", { class: "grade-label", text: p.label || "Sem dados" }),
  );
  const meter = evaluated
    ? h("div", { class: "meter", "aria-hidden": "true" }, h("span", { class: `meter-fill ${gradeClass(p.grade)}`, style: { width: `${p.score}%` } }))
    : null;
  const sevs = h(
    "ul",
    { class: "sev-counts", "aria-label": "Achados abertos por severidade" },
    SEVERITY_ORDER.filter((s) => s !== "info").map((s) => h("li", {}, sevChip(s, `${SEVERITY[s]} ${c[s] || 0}`))),
  );
  const prios = a.priorities || {};
  const whatIf = a.what_if && evaluated && a.what_if.score > p.score
    ? h(
        "p",
        { class: "what-if" },
        icon("target", 16),
        h("span", {}, `Fazendo ${a.what_if.actions === 1 ? "a primeira ação" : `as ${a.what_if.actions} primeiras ações`} do plano, a nota estimada vai de ${p.score} para `, h("strong", { text: `${a.what_if.score} (${a.what_if.grade})` }), "."),
      )
    : null;
  return h(
    "section",
    { class: "verdict", "aria-label": "Veredito" },
    gradeBlock,
    h(
      "div",
      { class: "verdict-body" },
      h("p", { class: "headline", text: n.headline || "" }),
      p.cap_reason ? h("p", { class: "cap", text: p.cap_reason }) : null,
      meter,
      whatIf,
      evaluated
        ? h(
            "div",
            { class: "verdict-counts" },
            sevs,
            h("p", { class: "prio-line" }, ["P1", "P2", "P3", "P4"].map((b) => h("span", { class: "prio" }, bandChip(b), ` ${prios[b] || 0}`)), c.triaged ? h("span", { class: "muted", text: ` · ${plural(c.triaged, "triado", "triados")}` }) : null),
          )
        : null,
      n.paragraphs?.length ? h("details", { class: "summary-text", open: true }, h("summary", { text: "Resumo da auditoria" }), n.paragraphs.map((t) => h("p", { text: t }))) : null,
    ),
  );
}

function diffBanner(view) {
  const diff = view.data.analysis?.diff;
  if (!diff) return null;
  const delta = diff.delta > 0 ? `+${diff.delta}` : String(diff.delta);
  return h(
    "aside",
    { class: "notice notice-info diff-banner" },
    icon("swap", 18),
    h(
      "p",
      {},
      `Desde a auditoria de ${dateTime(diff.previous_date)}: ${plural(diff.fixed.length, "corrigido", "corrigidos")}, ${plural(diff.new.length, "novo", "novos")} e ${plural(diff.persisting.length, "ainda aberto", "ainda abertos")}. Nota ${diff.score_before} para ${diff.score_after} (${delta}). `,
      h("a", { href: `#/comparar/${diff.previous_id}/${view.data.id}`, text: "Ver comparação" }),
    ),
  );
}

function tabsNav(view) {
  const a = view.data.analysis || {};
  const counts = {
    plano: a.plan?.length || 0,
    achados: view.data.findings?.length || 0,
    cenarios: a.scenarios?.length || 0,
    "pontos-fortes": a.narrative?.strengths?.length || 0,
  };
  return h(
    "nav",
    { class: "tabs", "aria-label": "Seções do resultado" },
    TABS.map((t) =>
      h(
        "a",
        { href: `#/resultado/${view.data.id}/${t.id}`, class: "tab", "aria-current": t.id === view.tab ? "page" : null },
        t.label,
        counts[t.id] !== undefined ? h("span", { class: "tab-count", text: String(counts[t.id]) }) : null,
      ),
    ),
  );
}

function tabContent(view, redraw) {
  switch (view.tab) {
    case "achados":
      return findingsTab(view, redraw);
    case "cenarios":
      return scenariosTab(view);
    case "pontos-fortes":
      return strengthsTab(view);
    case "conformidade":
      return complianceTab(view);
    case "inventario":
      return inventoryTab(view);
    case "linha-do-tempo":
      return timelineTab(view);
    default:
      return planTab(view);
  }
}

// -- plano de correção ---------------------------------------------------------------------

function planTab(view) {
  const plan = view.data.analysis?.plan || [];
  if (!plan.length) {
    return emptyState(
      view.data.analysis?.evaluated ? "Nada para corrigir" : "Sem plano: o alvo não pôde ser avaliado",
      view.data.analysis?.evaluated ? "Nenhum problema aberto nas verificações feitas. Mantenha auditorias periódicas." : view.data.analysis?.narrative?.headline || "Confira o alvo e tente de novo.",
    );
  }
  const list = h("ol", { class: "plan" });
  plan.forEach((action, index) => {
    const open = view.openAction ? view.openAction === action.group : index === 0;
    const meta = [action.area, `esforço ${action.effort_label.split(" ")[0].toLowerCase()}`, plural(action.count, "achado", "achados")];
    if (action.score_gain > 0) meta.push(`+${action.score_gain} pontos na nota`);
    list.append(
      h(
        "li",
        { class: "plan-item", id: `acao-${action.group}` },
        h(
          "details",
          { class: "action", open, on: { toggle: (e) => { if (e.currentTarget.open) view.openAction = action.group; } } },
          h(
            "summary",
            {},
            h("span", { class: "action-index", text: String(index + 1) }),
            h("span", { class: "action-head" }, h("span", { class: "action-title", text: action.title }), h("span", { class: "action-meta", text: meta.join(" · ") })),
            h("span", { class: "action-chips" }, bandChip(action.band), action.quick_win ? h("span", { class: "chip chip-quick", text: "Rápida" }) : null, action.kev ? h("span", { class: "chip chip-kev", text: "KEV" }) : null),
          ),
          h(
            "div",
            { class: "action-body" },
            h("p", { class: "band-text", text: action.band_text }),
            action.problems.map((problem) => problemBlock(problem)),
            action.fixes?.length ? fixTabs(action.fixes) : null,
          ),
        ),
      ),
    );
  });
  return h("div", {}, h("p", { class: "section-hint", text: "Ações em ordem de prioridade. Cada uma resolve um grupo de achados; os exemplos de configuração já consideram as tecnologias detectadas." }), list);
}

function assetList(assets, more) {
  if (!assets?.length) return null;
  const shown = assets.slice(0, 6);
  const rest = assets.length - shown.length + (more || 0);
  return h(
    "p",
    { class: "assets" },
    h("span", { class: "assets-label", text: "Onde: " }),
    shown.map((a, i) => [i ? ", " : "", h("code", { class: "break", text: a })]),
    rest > 0 ? h("span", { class: "muted", text: ` e mais ${rest}` }) : null,
  );
}

function problemBlock(problem) {
  return h(
    "div",
    { class: "problem" },
    h("h3", { class: "problem-title" }, sevChip(problem.severity), h("span", { text: problem.title })),
    problem.summary ? h("p", { text: problem.summary }) : null,
    assetList(problem.assets, problem.more_assets),
    problem.steps?.length ? h("ol", { class: "steps" }, problem.steps.map((s) => h("li", { text: s }))) : null,
    problem.verify ? h("p", { class: "verify" }, h("strong", { text: "Como verificar: " }), problem.verify) : null,
  );
}

function fixTabs(fixes) {
  const wrap = h("div", { class: "fixes" }, h("p", { class: "fixes-title", text: "Exemplo de correção" }));
  const codeBox = h("div", { class: "code-box" });
  const tabs = h("div", { class: "fix-tabs", role: "tablist", "aria-label": "Tecnologia" });
  let current = 0;
  const show = () => {
    clear(tabs);
    fixes.forEach((fx, i) => {
      tabs.append(h("button", { type: "button", role: "tab", class: "fix-tab", "aria-selected": i === current ? "true" : "false", on: { click: () => { current = i; show(); } } }, fx.label));
    });
    clear(codeBox).append(codeBlock(fixes[current].code, fixes[current].label));
  };
  show();
  if (fixes.length > 1) wrap.append(tabs);
  wrap.append(codeBox);
  return wrap;
}

function codeBlock(code, label = "") {
  const copy = button("Copiar", {
    kind: "code",
    iconName: "copy",
    attrs: { "aria-label": `Copiar exemplo ${label}`.trim() },
    onClick: async () => {
      const ok = await copyText(code);
      copy.querySelector("span").textContent = ok ? "Copiado" : "Não foi possível copiar";
      setTimeout(() => (copy.querySelector("span").textContent = "Copiar"), 1800);
    },
  });
  return h("div", { class: "code" }, copy, h("pre", {}, h("code", { text: code })));
}

// -- achados -------------------------------------------------------------------------------

const STATUS_FILTERS = {
  abertos: { label: "Abertos", test: (f) => f.status === "aberto" },
  todos: { label: "Todos", test: () => true },
  triados: { label: "Triados", test: (f) => f.status !== "aberto" },
};

function findingsTab(view, redraw) {
  const findings = view.data.findings || [];
  if (!findings.length) {
    return emptyState("Nenhum achado", view.data.analysis?.evaluated ? "As verificações não encontraram problemas." : "O alvo não respondeu às verificações.");
  }
  const list = h("ul", { class: "findings" });
  const count = h("p", { class: "muted count-line", "aria-live": "polite" });
  const search = h("input", { type: "search", class: "input", placeholder: "Buscar por título, ativo ou CVE", "aria-label": "Buscar achados", value: view.filters.text });
  const sevBar = h("div", { class: "filter-chips", role: "group", "aria-label": "Filtrar por severidade" });
  const statusSel = h("select", { class: "input input-sm", "aria-label": "Filtrar por situação" }, Object.entries(STATUS_FILTERS).map(([v, f]) => h("option", { value: v, text: f.label, selected: view.filters.status === v })));

  const drawSev = () => {
    clear(sevBar);
    for (const sev of SEVERITY_ORDER) {
      const on = view.filters.severities.has(sev);
      sevBar.append(
        h("button", { type: "button", class: `filter-chip sev-${sev}`, "aria-pressed": on ? "true" : "false", on: { click: () => { on ? view.filters.severities.delete(sev) : view.filters.severities.add(sev); drawSev(); drawList(); } } }, h("span", { class: "dot", "aria-hidden": "true" }), SEVERITY[sev]),
      );
    }
  };
  const drawList = () => {
    clear(list);
    const text = view.filters.text.toLowerCase();
    const statusTest = STATUS_FILTERS[view.filters.status].test;
    const shown = findings.filter(
      (f) =>
        statusTest(f) &&
        (!view.filters.severities.size || view.filters.severities.has(f.severity)) &&
        (!text || `${f.title} ${f.asset} ${f.check_id} ${(f.cves || []).join(" ")}`.toLowerCase().includes(text)),
    );
    count.textContent = shown.length === findings.length ? plural(findings.length, "achado", "achados") : `${shown.length} de ${findings.length} achados`;
    if (!shown.length) list.append(h("li", { class: "muted empty-inline", text: "Nenhum achado com estes filtros." }));
    for (const f of shown.slice(0, 500)) list.append(findingItem(view, f, redraw));
  };
  search.addEventListener("input", () => {
    view.filters.text = search.value;
    drawList();
  });
  statusSel.addEventListener("change", () => {
    view.filters.status = statusSel.value;
    drawList();
  });
  drawSev();
  drawList();
  return h("div", {}, h("div", { class: "toolbar" }, search, sevBar, statusSel), count, list);
}

function findingItem(view, f, redraw) {
  const body = h("div", { class: "finding-body" });
  const details = h(
    "details",
    { class: "finding", open: view.openFinding === f.fingerprint },
    h(
      "summary",
      {},
      h("span", { class: "finding-chips" }, sevChip(f.severity), bandChip(f.priority_label)),
      h("span", { class: "finding-head" }, h("span", { class: "finding-title", text: f.title }), h("span", { class: "finding-asset", text: f.asset })),
      h("span", { class: "finding-flags" }, f.kev ? h("span", { class: "chip chip-kev", title: "Exploração ativa conhecida (CISA KEV)", text: "KEV" }) : null, f.status !== "aberto" ? h("span", { class: "chip chip-status", text: TRIAGE[f.status] }) : null),
    ),
    body,
  );
  let loaded = false;
  const load = async () => {
    if (loaded) return;
    loaded = true;
    clear(body).append(h("p", { class: "muted", text: "Carregando explicação…" }));
    let entry = view.kb.get(f.check_id);
    if (!entry) {
      try {
        entry = await api(`/api/kb/${encodeURIComponent(f.check_id)}`);
        view.kb.set(f.check_id, entry);
      } catch {
        entry = null;
      }
    }
    clear(body);
    fillFinding(body, view, f, entry, redraw);
  };
  details.addEventListener("toggle", () => {
    if (details.open) {
      view.openFinding = f.fingerprint;
      load();
    } else if (view.openFinding === f.fingerprint) {
      view.openFinding = null;
    }
  });
  if (details.open) load();
  return h("li", {}, details);
}

function fillFinding(body, view, f, entry, redraw) {
  const meta = h(
    "dl",
    { class: "meta-grid" },
    h("div", {}, h("dt", { text: "Confiança" }), h("dd", { text: CONFIDENCE[f.confidence] || f.confidence })),
    h("div", {}, h("dt", { text: "Exposição" }), h("dd", { text: EXPOSURE[f.exposure] || f.exposure })),
    h("div", {}, h("dt", { text: "Prioridade" }), h("dd", { text: `${f.priority_label} (${f.priority}/100)` })),
    h("div", {}, h("dt", { text: "Visto pela primeira vez" }), h("dd", { text: dateTime(f.first_seen) })),
    h("div", {}, h("dt", { text: "Identificador" }), h("dd", {}, h("code", { text: f.check_id }))),
  );
  append(body, [
    entry?.explanation ? section("O que é", h("p", { text: entry.explanation })) : null,
    entry?.risk ? section("Risco", h("p", { text: entry.risk })) : null,
    f.evidence ? section("Evidência", h("pre", { class: "evidence" }, h("code", { text: f.evidence }))) : null,
    f.details && Object.keys(f.details).length ? section("Detalhes", detailsList(f.details)) : null,
    f.cves?.length
      ? section(
          "Vulnerabilidades conhecidas",
          h("p", { class: "cves" }, f.cves.map((cve, i) => [i ? ", " : "", externalLink(`https://nvd.nist.gov/vuln/detail/${cve}`, cve)]), f.kev ? h("span", { class: "kev-note", text: " · consta do catálogo CISA KEV (exploração ativa)" }) : null),
        )
      : null,
    meta,
    entry?.steps?.length
      ? section(
          "Como corrigir",
          h("ol", { class: "steps" }, entry.steps.map((s) => h("li", { text: s }))),
          entry.examples?.length ? fixTabs(entry.examples) : null,
          entry.verify ? h("p", { class: "verify" }, h("strong", { text: "Como verificar: " }), entry.verify) : null,
        )
      : null,
    entry?.references?.length ? section("Referências", h("ul", { class: "refs" }, entry.references.map((r) => h("li", {}, externalLink(r))))) : null,
    triageBox(view, f, redraw),
  ]);
}

function section(title, ...content) {
  return h("div", { class: "fsection" }, h("h4", { text: title }), ...content);
}

function detailsList(details) {
  return h(
    "dl",
    { class: "kv" },
    Object.entries(details).map(([k, v]) => h("div", {}, h("dt", { text: k.replaceAll("_", " ") }), h("dd", { class: "break", text: typeof v === "object" ? JSON.stringify(v) : String(v) }))),
  );
}

function triageBox(view, f, redraw) {
  let status = f.status;
  const note = h("input", { class: "input", placeholder: "Motivo (opcional): ex.: protegido pelo WAF", value: f.status_note || "", "aria-label": "Motivo da triagem", maxlength: "1000" });
  const options = h("div", { class: "seg seg-sm", role: "radiogroup", "aria-label": "Situação do achado" });
  const drawOptions = () => {
    clear(options);
    for (const [value, label] of Object.entries(TRIAGE)) {
      options.append(h("button", { type: "button", role: "radio", class: "seg-item", "aria-checked": value === status ? "true" : "false", on: { click: () => { status = value; drawOptions(); } } }, label));
    }
  };
  drawOptions();
  const save = button("Salvar triagem", {
    kind: "primary",
    onClick: async () => {
      save.disabled = true;
      try {
        view.data = await api(`/api/resultados/${view.data.id}/triagem`, { method: "POST", body: { fingerprint: f.fingerprint, status, nota: note.value } });
        view.openFinding = f.fingerprint;
        toast(status === "aberto" ? "Achado reaberto. A nota foi recalculada." : `Achado marcado como ${TRIAGE[status].toLowerCase()}. A nota foi recalculada.`, { kind: "ok" });
        redraw();
      } catch (error) {
        toast(error.message, { kind: "error" });
        save.disabled = false;
      }
    },
  });
  return h(
    "div",
    { class: "triage" },
    h("h4", { text: "Triagem" }),
    h("p", { class: "section-hint", text: "Vale para as próximas auditorias deste alvo. Achados aceitos ou falsos positivos saem da nota; um achado marcado como corrigido que reaparecer volta a ficar aberto." }),
    options,
    h("div", { class: "triage-row" }, note, save),
  );
}

// -- cenários, pontos fortes, conformidade, inventário e linha do tempo --------------------------

function scenariosTab(view) {
  const scenarios = view.data.analysis?.scenarios || [];
  if (!scenarios.length) {
    return emptyState("Nenhuma combinação perigosa", "O EIGAN cruza os achados procurando problemas que, juntos, abrem caminho para um ataque. Nada assim foi encontrado.");
  }
  return h(
    "ul",
    { class: "scenarios" },
    scenarios.map((s) =>
      h(
        "li",
        { class: "scenario" },
        h("h3", { class: "scenario-title" }, sevChip(s.severity), h("span", { text: s.title })),
        s.host ? h("p", { class: "muted break", text: `Em ${s.host}` }) : null,
        h("p", { text: s.narrative }),
        h("p", { class: "breaker" }, h("strong", { text: "Como quebrar a cadeia: " }), s.breaker),
        h("p", { class: "muted" }, "Achados envolvidos: ", s.titles.join("; ")),
      ),
    ),
  );
}

function strengthsTab(view) {
  const items = view.data.analysis?.narrative?.strengths || [];
  if (!items.length) return emptyState("Nenhum ponto forte registrado", "Os controles verificados e aprovados aparecem aqui.");
  return h(
    "ul",
    { class: "strengths" },
    items.map((s) => h("li", {}, icon("check", 18), h("div", {}, h("p", { text: s.text }), s.asset ? h("p", { class: "muted break", text: s.asset }) : null))),
  );
}

function complianceTab(view) {
  const c = view.data.analysis?.compliance;
  if (!c) return emptyState("Sem dados de conformidade", "");
  const table = (head, rows) => h("div", { class: "table-wrap" }, h("table", { class: "table" }, h("thead", {}, h("tr", {}, head.map((t) => h("th", { scope: "col", text: t })))), h("tbody", {}, rows)));
  const worstCell = (item) => (item.count ? sevChip(item.worst, `${item.count} · ${SEVERITY[item.worst]}`) : h("span", { class: "muted", text: "Nenhum problema encontrado" }));
  return h(
    "div",
    { class: "compliance" },
    h("h3", { class: "section-title", text: "OWASP Top 10 (2021)" }),
    table(["Categoria", "Achados"], c.owasp.map((o) => h("tr", {}, h("td", { text: o.label }), h("td", {}, worstCell(o))))),
    c.cis.length ? [h("h3", { class: "section-title", text: "CIS Controls v8" }), table(["Controle", "Descrição", "Achados"], c.cis.map((o) => h("tr", {}, h("td", { text: o.id }), h("td", { text: o.label }), h("td", {}, worstCell(o)))))] : null,
    c.cwe.length ? [h("h3", { class: "section-title", text: "CWE" }), h("ul", { class: "cwe-list" }, c.cwe.map((w) => h("li", {}, externalLink(w.url, w.id), h("span", { class: "muted", text: ` · ${plural(w.count, "achado", "achados")}: ${w.titles.join("; ")}` }))))] : null,
    h(
      "div",
      { class: "notice notice-info lgpd" },
      icon("shield", 18),
      h("div", {}, h("p", {}, h("strong", { text: `LGPD: ${plural(c.lgpd.count, "achado pode", "achados podem")} expor dados pessoais.` })), h("p", { text: c.lgpd.text }), c.lgpd.titles.length ? h("p", { class: "muted", text: c.lgpd.titles.join("; ") }) : null),
    ),
  );
}

function inventoryTab(view) {
  const sections = view.data.analysis?.inventory?.sections || [];
  if (!sections.length) return emptyState("Inventário vazio", "Hosts, portas, tecnologias e certificados descobertos aparecem aqui.");
  return h(
    "div",
    { class: "inventory" },
    sections.map((s) => {
      const columns = s.columns.slice(0, 6);
      return h(
        "section",
        { class: "inv-section" },
        h("h3", { class: "section-title" }, s.title, h("span", { class: "tab-count", text: String(s.count) })),
        h(
          "div",
          { class: "table-wrap" },
          h(
            "table",
            { class: "table" },
            h("thead", {}, h("tr", {}, h("th", { scope: "col", text: "Item" }), columns.map((col) => h("th", { scope: "col", text: col.replaceAll("_", " ") })))),
            h("tbody", {}, s.rows.map((r) => h("tr", {}, h("td", { class: "break", text: r.key }), columns.map((col) => h("td", { class: "break", text: r.fields[col] ?? "" }))))),
          ),
        ),
        s.truncated ? h("p", { class: "muted", text: "Lista truncada; o JSON tem tudo." }) : null,
      );
    }),
  );
}

const RUN_STATUS = { ok: "Concluída", erro: "Erro", tempo_esgotado: "Tempo esgotado", cancelada: "Cancelada" };

function timelineTab(view) {
  const d = view.data;
  const problems = (d.runs || []).filter((r) => r.status !== "ok");
  return h(
    "div",
    { class: "timeline-tab" },
    h("p", { class: "section-hint", text: `${plural(d.runs?.length || 0, "verificação executada", "verificações executadas")}. Cada linha abaixo é uma decisão do motor de regras com o motivo.` }),
    d.errors?.length ? h("div", { class: "notice notice-warn" }, icon("alert", 18), h("ul", {}, d.errors.map((e) => h("li", { text: e })))) : null,
    h("ol", { class: "timeline" }, (d.decisions || []).map((dec) => h("li", {}, h("time", { text: timeOnly(dec.at) }), h("span", { text: dec.text })))),
    problems.length
      ? [
          h("h3", { class: "section-title", text: "Verificações que não terminaram" }),
          h("div", { class: "table-wrap" }, h("table", { class: "table" }, h("thead", {}, h("tr", {}, ["Verificação", "Sobre", "Situação", "Mensagem"].map((t) => h("th", { scope: "col", text: t })))), h("tbody", {}, problems.map((r) => h("tr", {}, h("td", { text: r.name }), h("td", { class: "break", text: r.fact_key }), h("td", { text: RUN_STATUS[r.status] || r.status }), h("td", { class: "break", text: r.message })))))),
        ]
      : null,
  );
}
