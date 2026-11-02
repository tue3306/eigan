// Utilitários de interface: criação de elementos sem innerHTML, ícones, avisos e formatação.

const SVG_NS = "http://www.w3.org/2000/svg";

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key === "on") for (const [ev, fn] of Object.entries(value)) el.addEventListener(ev, fn);
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (key === "style") Object.assign(el.style, value); // objeto: a CSP bloqueia style="" inline
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, String(value));
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.firstChild.remove();
  return el;
}

const ICONS = {
  plus: ["M12 5v14", "M5 12h14"],
  pulse: ["M3 12h4l3-8 4 16 3-8h4"],
  clock: ["c12,12,9", "M12 7v5l3 2"],
  book: ["M5 4.5A1.5 1.5 0 0 1 6.5 3H19v15H6.5A1.5 1.5 0 0 0 5 19.5z", "M5 19.5A1.5 1.5 0 0 0 6.5 21H19", "M9 7h6"],
  sliders: ["M4 7h9", "M17 7h3", "c15,7,2", "M4 17h3", "M11 17h9", "c9,17,2"],
  info: ["c12,12,9", "M12 11v5", "M12 8h.01"],
  shield: ["M12 3l7 3v6c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6z"],
  check: ["M5 12.5l4.2 4.2L19 7"],
  x: ["M6 6l12 12", "M18 6L6 18"],
  copy: ["M9 9h10v11H9z", "M5 15V5a1 1 0 0 1 1-1h9"],
  download: ["M12 4v11", "M7 10l5 5 5-5", "M5 20h14"],
  external: ["M14 4h6v6", "M20 4l-9 9", "M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"],
  folder: ["M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"],
  trash: ["M4 7h16", "M10 11v6", "M14 11v6", "M6 7l1 13h10l1-13", "M9 7V4h6v3"],
  refresh: ["M20 11a8 8 0 1 0-2.3 5.7", "M20 4v7h-7"],
  search: ["c11,11,7", "M20 20l-3.5-3.5"],
  alert: ["M12 3.5l9.5 16.5h-19z", "M12 10v4.5", "M12 17.5h.01"],
  power: ["M12 3v9", "M6.3 6.3a8 8 0 1 0 11.4 0"],
  chevron: ["M9 6l6 6-6 6"],
  swap: ["M4 8h13", "M14 5l3 3-3 3", "M20 16H7", "M10 13l-3 3 3 3"],
  file: ["M6 3h8l5 5v13H6z", "M14 3v5h5"],
  stop: ["M7 7h10v10H7z"],
  target: ["c12,12,8", "c12,12,3"],
  layers: ["M12 3l9 5-9 5-9-5z", "M3 13l9 5 9-5"],
};

export function icon(name, size = 18) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  svg.classList.add("icon");
  for (const d of ICONS[name] || []) {
    let node;
    if (d.startsWith("c")) {
      const [cx, cy, r] = d.slice(1).split(",");
      node = document.createElementNS(SVG_NS, "circle");
      node.setAttribute("cx", cx);
      node.setAttribute("cy", cy);
      node.setAttribute("r", r);
    } else {
      node = document.createElementNS(SVG_NS, "path");
      node.setAttribute("d", d);
    }
    svg.append(node);
  }
  return svg;
}

export function button(label, { kind = "secondary", iconName = null, onClick = null, attrs = {} } = {}) {
  return h(
    "button",
    { type: "button", class: `btn btn-${kind}`, ...attrs, on: onClick ? { click: onClick } : undefined },
    iconName ? icon(iconName, 16) : null,
    label ? h("span", { text: label }) : null,
  );
}

// -- rótulos ------------------------------------------------------------------------------

export const SEVERITY = {
  critical: "Crítica",
  high: "Alta",
  medium: "Média",
  low: "Baixa",
  info: "Informativo",
};
export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
export const CONFIDENCE = { confirmed: "Confirmado", firm: "Provável", tentative: "Indício" };
export const EXPOSURE = {
  internet: "Exposto à Internet",
  interna: "Rede interna",
  local: "Máquina local",
  codigo: "Código-fonte",
  logs: "Evento em log",
};
export const TRIAGE = {
  aberto: "Aberto",
  aceito: "Risco aceito",
  falso_positivo: "Falso positivo",
  corrigido: "Corrigido",
};
export const KIND = {
  url: "Site ou aplicação web",
  host: "Servidor ou rede",
  local: "Esta máquina",
  projeto: "Pasta de projeto",
  logs: "Logs",
};
export const PROFILE = { rapido: "Rápido", padrao: "Padrão", completo: "Completo" };
export const BAND_HINT = {
  P1: "Imediata: corrigir em até 72 horas",
  P2: "Alta: corrigir em até 7 dias",
  P3: "Média: corrigir em até 30 dias",
  P4: "Baixa: planejar na próxima janela",
};

export function sevChip(severity, text = null) {
  return h(
    "span",
    { class: `chip sev sev-${severity}` },
    h("span", { class: "dot", "aria-hidden": "true" }),
    text ?? SEVERITY[severity] ?? severity,
  );
}

export function bandChip(band) {
  if (!band || band === "Info") return h("span", { class: "chip band band-info", text: "Info" });
  return h("span", { class: `chip band band-${band.toLowerCase()}`, title: BAND_HINT[band] || "", text: band });
}

export function gradeClass(grade) {
  if (!grade || grade === "—") return "grade-none";
  if (grade.startsWith("A")) return "grade-a";
  if (grade === "B") return "grade-b";
  if (grade === "C") return "grade-c";
  if (grade === "D" || grade === "E") return "grade-d";
  return "grade-f";
}

export function gradeBadge(grade, score = null) {
  return h(
    "span",
    { class: `grade-badge ${gradeClass(grade)}`, title: score === null ? "" : `${score}/100` },
    grade || "—",
  );
}

// -- formatação ---------------------------------------------------------------------------

export function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

export function dateTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
}

export function dateOnly(iso) {
  if (!iso) return "";
  // AAAA-MM-DD é um dia do calendário, não um instante: passar por Date o leria como
  // meia-noite UTC e mostraria o dia anterior em fusos a oeste (como o do Brasil).
  const day = /^(\d{4})-(\d{2})-(\d{2})(?:$|T)/.exec(String(iso));
  if (day) return `${day[3]}/${day[2]}/${day[1]}`;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("pt-BR");
}

export function duration(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  if (s < 1) return "menos de 1 s";
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  const rest = s % 60;
  if (m < 60) return rest ? `${m} min ${rest} s` : `${m} min`;
  const hours = Math.floor(m / 60);
  const mins = m % 60;
  return mins ? `${hours} h ${mins} min` : `${hours} h`;
}

export function timeOnly(value) {
  const d = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// -- avisos, cópia e confirmação --------------------------------------------------------------

export function toast(message, { kind = "info", action = null, timeout = 4500 } = {}) {
  const host = document.getElementById("toasts");
  const item = h(
    "div",
    { class: `toast toast-${kind}`, role: kind === "error" ? "alert" : "status" },
    h("span", { class: "toast-text", text: message }),
    action ? button(action.label, { kind: "ghost", onClick: () => { action.run(); item.remove(); } }) : null,
    h("button", { type: "button", class: "toast-close", "aria-label": "Fechar aviso", on: { click: () => item.remove() } }, icon("x", 14)),
  );
  host.append(item);
  if (timeout) setTimeout(() => item.remove(), timeout);
  return item;
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = h("textarea", { class: "visually-hidden", readonly: true });
    area.value = text;
    document.body.append(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    area.remove();
    return ok;
  }
}

export function confirmDialog({ title, text, confirmLabel = "Confirmar", danger = false }) {
  return new Promise((resolve) => {
    const dialog = h("dialog", { class: "dialog", "aria-labelledby": "dialog-title" });
    const done = (value) => {
      dialog.close();
      dialog.remove();
      resolve(value);
    };
    append(dialog, [
      h("h2", { id: "dialog-title", class: "dialog-title", text: title }),
      text ? h("p", { class: "dialog-text", text }) : null,
      h(
        "div",
        { class: "dialog-actions" },
        button("Cancelar", { kind: "secondary", onClick: () => done(false) }),
        button(confirmLabel, { kind: danger ? "danger" : "primary", onClick: () => done(true) }),
      ),
    ]);
    dialog.addEventListener("cancel", (ev) => {
      ev.preventDefault();
      done(false);
    });
    document.body.append(dialog);
    dialog.showModal();
    dialog.querySelector(".btn-secondary").focus();
  });
}

export function emptyState(title, text, ...actions) {
  return h(
    "div",
    { class: "empty" },
    h("p", { class: "empty-title", text: title }),
    text ? h("p", { class: "empty-text", text }) : null,
    actions.length ? h("div", { class: "empty-actions" }, ...actions) : null,
  );
}

export function loading(text = "Carregando…") {
  return h("div", { class: "loading", role: "status" }, h("span", { class: "spinner", "aria-hidden": "true" }), text);
}

export function errorBox(message, retry = null) {
  return h(
    "div",
    { class: "notice notice-error", role: "alert" },
    icon("alert", 18),
    h("div", {}, h("p", { text: message }), retry ? button("Tentar de novo", { kind: "secondary", iconName: "refresh", onClick: retry }) : null),
  );
}

export function externalLink(href, text) {
  const safe = /^https?:\/\//i.test(href) ? href : null;
  if (!safe) return h("span", { text: text || href });
  return h("a", { href: safe, target: "_blank", rel: "noopener noreferrer", class: "ext" }, text || href, icon("external", 13));
}
