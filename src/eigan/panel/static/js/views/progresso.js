// Tela "Auditoria em andamento": progresso, raciocínio do motor e achados ao vivo.

import { api, jobEvents } from "../api.js";
import { KIND, PROFILE, SEVERITY_ORDER, append, button, clear, confirmDialog, errorBox, h, icon, sevChip, timeOnly } from "../ui.js";

const MAX_LINES = 400;

export async function renderProgress(main, jobId) {
  const { job } = await api(`/api/auditorias/${jobId}`);
  const title = h("h1", { class: "break", text: `Auditando ${job.target}` });
  const meta = h("p", { class: "lead", text: `${KIND[job.kind] || job.kind_label} · perfil ${PROFILE[job.profile] || job.profile}` });
  const cancelBtn = button("Cancelar auditoria", {
    kind: "secondary",
    iconName: "stop",
    onClick: async () => {
      const ok = await confirmDialog({
        title: "Cancelar esta auditoria?",
        text: "As verificações em curso terminam e o resultado parcial fica salvo no histórico.",
        confirmLabel: "Cancelar auditoria",
        danger: true,
      });
      if (!ok) return;
      cancelBtn.disabled = true;
      statusText.textContent = "Cancelando… aguardando as verificações em curso.";
      try {
        await api(`/api/auditorias/${jobId}/cancelar`, { method: "POST" });
      } catch (error) {
        cancelBtn.disabled = false;
        statusText.textContent = error.message;
      }
    },
  });

  const bar = h("div", { class: "progress-fill" });
  const progress = h("div", { class: "progress", role: "progressbar", "aria-label": "Progresso da auditoria", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": "0" }, bar);
  const statusText = h("p", { class: "progress-text", text: "Preparando as primeiras verificações…" });
  const counters = h("div", { class: "counters", "aria-live": "polite" });
  const counts = {}; // os eventos são reenviados desde o início e reconstroem a contagem
  const drawCounters = () => {
    clear(counters);
    for (const sev of SEVERITY_ORDER) counters.append(sevChip(sev, `${labelFor(sev)} ${counts[sev] || 0}`));
  };
  drawCounters();

  const decisions = h("ol", { class: "timeline live", "aria-label": "Raciocínio do motor" });
  const findings = h("ul", { class: "live-findings", "aria-label": "Achados até agora" });
  const emptyFindings = h("p", { class: "muted", text: "Nenhum problema encontrado até agora." });
  const doneBox = h("div", { class: "done-box", hidden: true });

  append(main, [
    h("header", { class: "page-head with-actions" }, h("div", {}, title, meta), h("div", { class: "head-actions" }, cancelBtn)),
    h("section", { class: "surface progress-surface" }, progress, statusText, counters),
    doneBox,
    h(
      "div",
      { class: "two-col" },
      h("section", { "aria-labelledby": "raciocinio" }, h("h2", { id: "raciocinio", class: "section-title", text: "Raciocínio do motor" }), h("p", { class: "section-hint", text: "Cada descoberta dispara as verificações certas. É assim que o EIGAN decide o que fazer, sem IA." }), decisions),
      h("section", { "aria-labelledby": "achados-vivo" }, h("h2", { id: "achados-vivo", class: "section-title", text: "Achados até agora" }), emptyFindings, findings),
    ),
  ]);

  let finished = false;
  const setProgress = (done, total) => {
    const pct = total ? Math.min(100, Math.round((done / total) * 100)) : 0;
    bar.style.width = `${pct}%`;
    progress.setAttribute("aria-valuenow", String(pct));
    if (!finished) statusText.textContent = total ? `${done} de ${total} verificações concluídas` : "Preparando as primeiras verificações…";
  };
  setProgress(job.done, job.total);

  const addDecision = (text, t) => {
    decisions.append(h("li", {}, h("time", { text: timeOnly(t) }), h("span", { text })));
    while (decisions.children.length > MAX_LINES) decisions.firstElementChild.remove();
  };

  const finish = (status, error) => {
    if (finished) return;
    finished = true;
    cancelBtn.hidden = true;
    progress.classList.add("is-done");
    clear(doneBox);
    doneBox.hidden = false;
    if (status === "erro") {
      statusText.textContent = "A auditoria parou por um erro.";
      doneBox.append(errorBox(error || "Erro inesperado. Veja o log do EIGAN.", () => (location.hash = "#/nova")));
      return;
    }
    bar.style.width = "100%";
    statusText.textContent = status === "cancelada" ? "Auditoria cancelada. O resultado parcial foi salvo." : "Auditoria concluída.";
    const link = h("a", { class: "btn btn-primary", href: `#/resultado/${jobId}` }, icon("check", 16), h("span", { text: "Ver resultado" }));
    doneBox.append(h("div", { class: "notice notice-ok" }, h("p", { text: "Análise pronta: nota, plano de correção e relatórios." }), link));
    setTimeout(() => {
      if (location.hash === `#/auditoria/${jobId}`) location.hash = `#/resultado/${jobId}`;
    }, 1200);
  };

  const source = jobEvents(
    jobId,
    (event) => {
      switch (event.type) {
        case "decision":
          addDecision(event.text, event.t);
          break;
        case "progress":
        case "check_finished":
          setProgress(event.done, event.total);
          break;
        case "finding": {
          const f = event.finding || {};
          counts[f.severity] = (counts[f.severity] || 0) + 1;
          drawCounters();
          emptyFindings.hidden = true;
          if (f.severity !== "info") {
            findings.prepend(h("li", {}, sevChip(f.severity), h("div", { class: "live-finding" }, h("strong", { text: f.title }), h("span", { class: "muted break", text: f.asset }))));
            while (findings.children.length > MAX_LINES) findings.lastElementChild.remove();
          }
          break;
        }
        case "scan_finished":
          if (!finished) statusText.textContent = "Analisando resultados e montando o plano…";
          break;
        case "job_finished":
          finish(event.status, event.error);
          break;
        default:
          break;
      }
    },
    () => {
      if (!finished) api(`/api/auditorias/${jobId}`).then(({ job: j }) => j.status !== "em_andamento" && j.status !== "na_fila" && finish(j.status, j.error)).catch(() => {});
    },
  );
  if (["concluida", "cancelada", "erro"].includes(job.status)) finish(job.status, job.error);
  return () => source.close();
}

function labelFor(sev) {
  return { critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa", info: "Info" }[sev];
}
