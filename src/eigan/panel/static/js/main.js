// Painel do EIGAN: navegação por hash, carregamento das telas e indicador de auditorias.

import { api } from "./api.js";
import { clear, h, icon, loading, errorBox } from "./ui.js";
import { renderNew } from "./views/nova.js";
import { renderProgress } from "./views/progresso.js";
import { renderResult } from "./views/resultado.js";
import { renderHistory, renderCompare } from "./views/historico.js";
import { renderChecks } from "./views/checagens.js";
import { renderSettings } from "./views/configuracoes.js";
import { renderAbout } from "./views/sobre.js";

export const state = { info: null };

const NAV = [
  { href: "#/nova", label: "Nova auditoria", icon: "plus", match: /^#\/(nova|auditoria)/ },
  { href: "#/historico", label: "Histórico", icon: "clock", match: /^#\/(historico|resultado|comparar)/ },
  { href: "#/checagens", label: "Verificações", icon: "book", match: /^#\/checagens/ },
  { href: "#/configuracoes", label: "Configurações", icon: "sliders", match: /^#\/configuracoes/ },
  { href: "#/sobre", label: "Sobre", icon: "info", match: /^#\/sobre/ },
];

const ROUTES = [
  [/^#\/nova$/, (main) => renderNew(main, state)],
  [/^#\/auditoria\/([a-f0-9]{6,32})$/, (main, m) => renderProgress(main, m[1])],
  [/^#\/resultado\/([\w-]{6,40})(?:\/([a-z-]+))?$/, (main, m) => renderResult(main, m[1], m[2] || "plano")],
  [/^#\/historico$/, (main) => renderHistory(main)],
  [/^#\/comparar\/([\w-]{6,40})\/([\w-]{6,40})$/, (main, m) => renderCompare(main, m[1], m[2])],
  [/^#\/checagens$/, (main) => renderChecks(main)],
  [/^#\/configuracoes$/, (main) => renderSettings(main, state)],
  [/^#\/sobre$/, (main) => renderAbout(main, state)],
];

let cleanup = null;
let lastRoute = "";

function buildNav() {
  const nav = document.getElementById("nav");
  clear(nav);
  for (const item of NAV) {
    nav.append(h("a", { href: item.href, class: "nav-item", dataset: { href: item.href } }, icon(item.icon, 18), h("span", { text: item.label })));
  }
}

function markNav(hash) {
  for (const [index, el] of [...document.querySelectorAll(".nav-item")].entries()) {
    if (NAV[index].match.test(hash)) el.setAttribute("aria-current", "page");
    else el.removeAttribute("aria-current");
  }
}

async function route() {
  const hash = location.hash || "#/nova";
  if (hash === "#/" || hash === "#") {
    location.replace("#/nova");
    return;
  }
  const routeKey = hash.replace(/^(#\/resultado\/[\w-]+)\/[a-z-]+$/, "$1");
  const sameScreen = routeKey === lastRoute;
  lastRoute = routeKey;
  markNav(hash);
  const main = document.getElementById("main");
  const match = ROUTES.map(([re, fn]) => [hash.match(re), fn]).find(([m]) => m);
  if (sameScreen && hash.startsWith("#/resultado/")) {
    // Troca de aba na mesma tela: a própria tela reage ao evento.
    window.dispatchEvent(new CustomEvent("eigan:tab", { detail: hash.split("/")[3] || "plano" }));
    return;
  }
  if (typeof cleanup === "function") cleanup();
  cleanup = null;
  clear(main);
  if (!match) {
    main.append(errorBox("Página não encontrada."));
    return;
  }
  const [m, render] = match;
  try {
    cleanup = await render(main, m);
  } catch (error) {
    clear(main);
    main.append(errorBox(error.message || "Não foi possível abrir esta tela.", () => route()));
  }
  if (!sameScreen) {
    main.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }
}

async function pollRunning() {
  const el = document.getElementById("running");
  try {
    const { jobs } = await api("/api/auditorias");
    const active = jobs.filter((j) => j.status === "em_andamento" || j.status === "na_fila");
    if (active.length) {
      el.hidden = false;
      el.href = `#/auditoria/${active[0].id}`;
      clear(el).append(h("span", { class: "pulse-dot", "aria-hidden": "true" }), active.length === 1 ? "1 auditoria em andamento" : `${active.length} auditorias em andamento`);
    } else {
      el.hidden = true;
    }
  } catch {
    el.hidden = true;
  }
}

async function start() {
  buildNav();
  const main = document.getElementById("main");
  main.append(loading("Abrindo o painel…"));
  try {
    state.info = await api("/api/info");
  } catch (error) {
    clear(main).append(errorBox(error.message, () => location.reload()));
    return;
  }
  window.addEventListener("hashchange", route);
  await route();
  pollRunning();
  setInterval(pollRunning, 4000);
}

start();
