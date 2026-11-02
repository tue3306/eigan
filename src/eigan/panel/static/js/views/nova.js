// Tela "Nova auditoria": alvo, tipo, perfil, opções e autorização.

import { api } from "../api.js";
import { KIND, PROFILE, append, button, clear, dateOnly, dateTime, gradeBadge, h, icon, plural, toast } from "../ui.js";

const EXAMPLES = [
  { label: "Site", value: "https://", kind: "url" },
  { label: "Servidor ou rede", value: "", kind: "host" },
  { label: "Esta máquina", value: "local", kind: "local" },
  { label: "Pasta de projeto", value: "", kind: "projeto" },
  { label: "Logs", value: "", kind: "logs" },
];

const PLACEHOLDER = {
  "": "https://seusite.com.br, 10.0.0.0/24, local ou C:\\projetos\\app",
  url: "https://seusite.com.br",
  host: "servidor.empresa.local, 10.0.0.5 ou 10.0.0.0/24",
  local: "local",
  projeto: "Caminho da pasta, ex.: C:\\projetos\\app ou /srv/app",
  logs: "Arquivo ou pasta de logs, ex.: /var/log/nginx",
};

export async function renderNew(main, state) {
  const info = state.info;
  const form = h("form", { class: "audit-form", novalidate: true });
  const targetInput = h("input", {
    id: "alvo",
    name: "alvo",
    class: "input input-lg",
    autocomplete: "off",
    spellcheck: "false",
    placeholder: PLACEHOLDER[""],
    "aria-describedby": "alvo-dica",
  });
  const hint = h("p", { id: "alvo-dica", class: "field-hint", text: "O tipo é detectado automaticamente." });
  const kindSelect = h(
    "select",
    { id: "tipo", class: "input" },
    h("option", { value: "", text: "Detectar automaticamente" }),
    Object.entries(KIND).map(([value, label]) => h("option", { value, text: label })),
  );
  let detected = "";
  let profile = info.default_profile || "padrao";

  const profileHelp = h("p", { class: "field-hint", id: "perfil-dica" });
  const profileGroup = h("div", { class: "seg", role: "radiogroup", "aria-label": "Perfil", "aria-describedby": "perfil-dica" });
  const renderProfiles = () => {
    clear(profileGroup);
    for (const p of info.profiles) {
      const selected = p.id === profile;
      profileGroup.append(
        h(
          "button",
          {
            type: "button",
            role: "radio",
            "aria-checked": selected ? "true" : "false",
            class: "seg-item",
            on: { click: () => { profile = p.id; renderProfiles(); } },
          },
          p.label,
        ),
      );
      if (selected) profileHelp.textContent = p.help;
    }
  };
  renderProfiles();

  const portsSelect = h(
    "select",
    { id: "portas", class: "input" },
    h("option", { value: "", text: "Conforme o perfil" }),
    h("option", { value: "top100", text: "100 portas mais comuns" }),
    h("option", { value: "top1000", text: "1.000 portas mais comuns" }),
    h("option", { value: "todas", text: "Todas (65.535, mais lento)" }),
    h("option", { value: "custom", text: "Lista personalizada" }),
  );
  const portsCustom = h("input", { id: "portas-lista", class: "input", placeholder: "22,80,443,8000-8100", hidden: true, "aria-label": "Portas personalizadas" });
  portsSelect.addEventListener("change", () => {
    portsCustom.hidden = portsSelect.value !== "custom";
    if (!portsCustom.hidden) portsCustom.focus();
  });
  const includePorts = h("input", { type: "checkbox", id: "incluir-portas" });
  const authorized = h("input", { type: "checkbox", id: "autorizado" });
  const authRow = h(
    "div",
    { class: "auth" },
    h("label", { class: "check", for: "autorizado" }, authorized, h("span", { text: "Tenho autorização para avaliar este alvo" })),
    h("p", { class: "field-hint", text: "Avalie somente sistemas seus ou com permissão por escrito. As verificações são não intrusivas: só leem o que um visitante comum veria." }),
  );
  const errorBox = h("p", { class: "form-error", role: "alert", hidden: true });
  const submit = h("button", { type: "submit", class: "btn btn-primary btn-lg" }, icon("shield", 18), h("span", { text: "Iniciar auditoria" }));

  const effectiveKind = () => kindSelect.value || detected;
  const updateKindUi = () => {
    const kind = effectiveKind();
    targetInput.placeholder = PLACEHOLDER[kindSelect.value] || PLACEHOLDER[""];
    authRow.hidden = !(kind === "url" || kind === "host" || kind === "");
    includeRow.hidden = kind !== "url";
    pickRow.hidden = !(kind === "projeto" || kind === "logs" || kind === "");
  };

  let detectTimer = null;
  targetInput.addEventListener("input", () => {
    errorBox.hidden = true;
    clearTimeout(detectTimer);
    const value = targetInput.value.trim();
    if (!value) {
      detected = "";
      hint.textContent = "O tipo é detectado automaticamente.";
      updateKindUi();
      return;
    }
    detectTimer = setTimeout(async () => {
      try {
        const res = await api(`/api/detectar?alvo=${encodeURIComponent(value)}`);
        detected = res.kind || "";
        hint.textContent = res.kind ? `Detectado: ${KIND[res.kind] || res.label}.` : res.erro || "Não reconhecido. Confira o endereço ou caminho.";
      } catch {
        hint.textContent = "";
      }
      updateKindUi();
    }, 250);
  });
  kindSelect.addEventListener("change", updateKindUi);

  const pick = async (mode) => {
    try {
      const res = await api("/api/escolher-caminho", { method: "POST", body: { modo: mode } });
      if (res.caminho) {
        targetInput.value = res.caminho;
        kindSelect.value = mode === "arquivo" ? "logs" : kindSelect.value || "";
        targetInput.dispatchEvent(new Event("input"));
      }
    } catch (error) {
      toast(error.message, { kind: "error" });
    }
  };
  const pickRow = h(
    "div",
    { class: "pick-row" },
    button("Escolher pasta…", { kind: "secondary", iconName: "folder", onClick: () => pick("pasta") }),
    button("Escolher arquivo de log…", { kind: "secondary", iconName: "file", onClick: () => pick("arquivo") }),
  );
  const includeRow = h("label", { class: "check", for: "incluir-portas" }, includePorts, h("span", { text: "Também varrer as portas do servidor do site" }));

  const quick = h(
    "div",
    { class: "quick", role: "group", "aria-label": "Atalhos de tipo" },
    EXAMPLES.map((ex) =>
      h(
        "button",
        {
          type: "button",
          class: "quick-item",
          on: {
            click: () => {
              kindSelect.value = ex.kind;
              if (ex.value || ex.kind === "local") targetInput.value = ex.value;
              else if (targetInput.value === "https://" || targetInput.value === "local") targetInput.value = "";
              targetInput.dispatchEvent(new Event("input"));
              updateKindUi();
              targetInput.focus();
            },
          },
        },
        ex.label,
      ),
    ),
  );

  append(form, [
    h("div", { class: "field" }, h("label", { class: "label", for: "alvo", text: "O que você quer auditar?" }), quick, targetInput, hint),
    pickRow,
    h(
      "div",
      { class: "field-grid" },
      h("div", { class: "field" }, h("label", { class: "label", for: "tipo", text: "Tipo de alvo" }), kindSelect),
      h("div", { class: "field" }, h("span", { class: "label", id: "perfil-rotulo", text: "Profundidade" }), profileGroup, profileHelp),
    ),
    h(
      "details",
      { class: "advanced" },
      h("summary", { text: "Opções de rede" }),
      h(
        "div",
        { class: "advanced-body" },
        h("div", { class: "field" }, h("label", { class: "label", for: "portas", text: "Portas a verificar" }), portsSelect, portsCustom),
        includeRow,
      ),
    ),
    authRow,
    errorBox,
    h("div", { class: "form-actions" }, submit),
  ]);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorBox.hidden = true;
    const alvo = targetInput.value.trim();
    if (!alvo || alvo === "https://") {
      errorBox.textContent = "Informe o que deseja auditar.";
      errorBox.hidden = false;
      targetInput.focus();
      return;
    }
    const kind = effectiveKind();
    const needsAuth = kind === "url" || kind === "host" || kind === "";
    if (needsAuth && !authorized.checked) {
      errorBox.textContent = "Confirme que você tem autorização para avaliar este alvo.";
      errorBox.hidden = false;
      authorized.focus();
      return;
    }
    let portas = portsSelect.value === "custom" ? portsCustom.value.trim() : portsSelect.value;
    submit.disabled = true;
    submit.querySelector("span").textContent = "Iniciando…";
    try {
      const { job } = await api("/api/auditorias", {
        method: "POST",
        body: {
          alvo,
          tipo: kindSelect.value || null,
          perfil: profile,
          portas: portas || null,
          incluir_portas: includePorts.checked,
          autorizado: needsAuth ? authorized.checked : true,
        },
      });
      location.hash = `#/auditoria/${job.id}`;
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.hidden = false;
      submit.disabled = false;
      submit.querySelector("span").textContent = "Iniciar auditoria";
    }
  });

  const recent = h("section", { class: "side-col", "aria-labelledby": "recentes" }, h("h2", { id: "recentes", class: "section-title", text: "Alvos recentes" }));
  const facts = h(
    "section",
    { class: "side-col facts", "aria-labelledby": "o-que" },
    h("h2", { id: "o-que", class: "section-title", text: "O que o EIGAN verifica" }),
    h(
      "ul",
      { class: "facts-list" },
      h("li", {}, h("strong", { text: String(info.checks) }), info.checks === 1 ? " verificação automática" : " verificações automáticas"),
      h("li", {}, h("strong", { text: String(info.kb_entries) }), info.kb_entries === 1 ? " tipo de problema com explicação e correção" : " tipos de problema com explicação e correção"),
      info.kev_catalog?.publicado ? h("li", {}, "Catálogo CISA KEV de ", h("strong", { text: dateOnly(info.kev_catalog.publicado) })) : null,
      h("li", { text: "Sem IA e sem envio de dados: tudo roda nesta máquina." }),
    ),
  );

  append(main, [
    h(
      "header",
      { class: "page-head" },
      h("h1", { text: "Nova auditoria" }),
      h("p", { class: "lead", text: "Informe um site, servidor, rede, pasta de projeto ou arquivo de log. O EIGAN escolhe as verificações, prioriza os problemas e explica como corrigir cada um." }),
    ),
    h("div", { class: "new-layout" }, h("section", { class: "surface form-surface", "aria-label": "Dados da auditoria" }, form), h("div", { class: "side" }, recent, facts)),
  ]);
  updateKindUi();
  targetInput.focus();

  try {
    const { targets } = await api("/api/alvos");
    if (!targets.length) {
      recent.append(h("p", { class: "muted", text: "As auditorias feitas aparecem aqui para repetir com um clique." }));
    } else {
      const list = h("ul", { class: "recent-list" });
      for (const t of targets.slice(0, 8)) {
        list.append(
          h(
            "li",
            { class: "recent-item" },
            gradeBadge(t.grade, t.score),
            h(
              "div",
              { class: "recent-main" },
              h("a", { href: `#/resultado/${t.id}`, class: "recent-target", text: t.target, title: t.target }),
              h("span", { class: "recent-meta", text: `${KIND[t.kind] || t.kind} · ${dateTime(t.started_at)} · ${plural(t.total, "auditoria", "auditorias")}` }),
            ),
            button("", {
              kind: "icon",
              iconName: "refresh",
              attrs: { title: "Usar este alvo de novo", "aria-label": `Auditar ${t.target} de novo` },
              onClick: () => {
                targetInput.value = t.target;
                kindSelect.value = t.kind;
                profile = t.profile in PROFILE ? t.profile : profile;
                renderProfiles();
                targetInput.dispatchEvent(new Event("input"));
                updateKindUi();
                targetInput.focus();
              },
            }),
          ),
        );
      }
      recent.append(list);
    }
  } catch {
    recent.append(h("p", { class: "muted", text: "Não foi possível carregar o histórico." }));
  }
  return null;
}
