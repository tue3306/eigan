// Tela "Configurações": perfil padrão, limites de rede e de arquivos, pastas de dados.

import { api } from "../api.js";
import { PROFILE, append, button, h, toast } from "../ui.js";

const GROUPS = [
  {
    title: "Auditoria",
    fields: [
      ["profile", "Perfil padrão", "Profundidade usada quando nenhuma é escolhida."],
      ["workers", "Verificações em paralelo", "Mais rápido com valores maiores; use menos em máquinas modestas."],
      ["scan_timeout", "Tempo máximo da auditoria (s)", "Ao atingir o limite, o resultado parcial é salvo."],
    ],
  },
  {
    title: "Sites e HTTP",
    fields: [
      ["http_timeout", "Tempo limite por requisição (s)", ""],
      ["http_per_host", "Requisições simultâneas por servidor", "Valores baixos são mais gentis com o servidor."],
      ["http_delay", "Pausa entre requisições (s)", "Use 0,2 a 1 s em servidores sensíveis."],
      ["http_max_bytes", "Tamanho máximo lido por resposta (bytes)", ""],
      ["max_http_services", "Máximo de serviços web por auditoria", ""],
      ["user_agent", "Identificação (User-Agent)", "Ajuda o dono do servidor a reconhecer a auditoria nos logs."],
    ],
  },
  {
    title: "Portas e rede",
    fields: [
      ["ports", "Portas", "auto (conforme o perfil), top100, top1000, todas ou lista como 22,80,8000-8100."],
      ["port_timeout", "Tempo limite por porta (s)", ""],
      ["port_workers", "Conexões simultâneas na varredura", ""],
      ["max_network_hosts", "Máximo de hosts por rede", ""],
      ["include_ports_for_url", "Varrer portas também em alvos de site", ""],
    ],
  },
  {
    title: "Código e logs",
    fields: [
      ["max_files", "Máximo de arquivos lidos", ""],
      ["max_file_bytes", "Tamanho máximo por arquivo (bytes)", ""],
      ["skip_dirs", "Pastas ignoradas", "Separadas por vírgula."],
      ["max_log_lines", "Máximo de linhas de log", ""],
    ],
  },
];

export async function renderSettings(main, state) {
  const { settings, defaults } = await api("/api/configuracoes");
  const inputs = new Map();
  const form = h("form", { class: "settings-form", novalidate: true });

  const control = (key) => {
    const id = `cfg-${key}`;
    const value = settings[key];
    if (key === "profile") {
      return h("select", { id, class: "input" }, Object.entries(PROFILE).map(([v, l]) => h("option", { value: v, text: l, selected: v === value })));
    }
    if (typeof defaults[key] === "boolean") return h("input", { id, type: "checkbox", checked: Boolean(value) });
    if (typeof defaults[key] === "number") return h("input", { id, class: "input", type: "number", step: Number.isInteger(defaults[key]) ? "1" : "0.1", min: "0", value: String(value) });
    return h("input", { id, class: "input", type: "text", value: String(value ?? ""), spellcheck: "false" });
  };

  for (const group of GROUPS) {
    const fieldset = h("fieldset", { class: "settings-group" }, h("legend", { text: group.title }));
    for (const [key, label, help] of group.fields) {
      if (!(key in settings)) continue;
      const input = control(key);
      inputs.set(key, input);
      const helpId = help ? `ajuda-${key}` : null;
      if (helpId) input.setAttribute("aria-describedby", helpId);
      if (input.type === "checkbox") {
        fieldset.append(h("div", { class: "field" }, h("label", { class: "check", for: input.id }, input, h("span", { text: label })), help ? h("p", { id: helpId, class: "field-hint", text: help }) : null));
      } else {
        fieldset.append(h("div", { class: "field" }, h("label", { class: "label", for: input.id, text: label }), input, help ? h("p", { id: helpId, class: "field-hint", text: help }) : null));
      }
    }
    form.append(fieldset);
  }

  const collect = () => {
    const out = {};
    for (const [key, input] of inputs) {
      if (input.type === "checkbox") out[key] = input.checked;
      else if (input.type === "number") out[key] = Number(String(input.value).replace(",", "."));
      else out[key] = input.value;
    }
    return out;
  };
  const save = h("button", { type: "submit", class: "btn btn-primary" }, h("span", { text: "Salvar configurações" }));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      const res = await api("/api/configuracoes", { method: "PUT", body: { settings: collect() } });
      for (const [key, input] of inputs) {
        if (input.type === "checkbox") input.checked = Boolean(res.settings[key]);
        else input.value = String(res.settings[key]);
      }
      if (state.info) state.info.default_profile = res.settings.profile;
      toast("Configurações salvas. Valores fora dos limites foram ajustados.", { kind: "ok" });
    } catch (error) {
      toast(error.message, { kind: "error" });
    } finally {
      save.disabled = false;
    }
  });
  const restore = button("Restaurar padrões", {
    kind: "secondary",
    onClick: () => {
      for (const [key, input] of inputs) {
        if (input.type === "checkbox") input.checked = Boolean(defaults[key]);
        else input.value = String(defaults[key]);
      }
      toast("Valores padrão preenchidos. Salve para aplicar.");
    },
  });
  form.append(h("div", { class: "form-actions" }, save, restore));

  const openFolder = (pasta) => api("/api/abrir-pasta", { method: "POST", body: { pasta } }).catch((e) => toast(e.message, { kind: "error" }));
  append(main, [
    h("header", { class: "page-head" }, h("h1", { text: "Configurações" }), h("p", { class: "lead", text: "Ajuste a profundidade e o ritmo das verificações. Os valores valem para as próximas auditorias." })),
    h("div", { class: "settings-layout" }, h("section", { class: "surface" }, form), h(
      "aside",
      { class: "side-col" },
      h("h2", { class: "section-title", text: "Pastas do EIGAN" }),
      h("p", { class: "muted", text: "Histórico, configurações e relatórios ficam nesta máquina." }),
      h("p", { class: "path break" }, h("code", { text: state.info?.data_dir || "" })),
      h("div", { class: "stack" }, button("Abrir pasta de relatórios", { kind: "secondary", iconName: "folder", onClick: () => openFolder("relatorios") }), button("Abrir pasta de dados", { kind: "secondary", iconName: "folder", onClick: () => openFolder("dados") })),
    )),
  ]);
  return null;
}
