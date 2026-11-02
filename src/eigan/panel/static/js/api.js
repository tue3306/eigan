// Acesso à API local do painel. O token vem embutido na página servida pelo próprio EIGAN.

const TOKEN = document.querySelector('meta[name="eigan-token"]')?.content || "";

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

export async function api(path, { method = "GET", body } = {}) {
  let response;
  try {
    response = await fetch(path, {
      method,
      headers: {
        "X-EIGAN-Token": TOKEN,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      cache: "no-store",
    });
  } catch {
    throw new ApiError("Sem conexão com o EIGAN. Verifique se a janela do EIGAN continua aberta.", 0);
  }
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (!response.ok) {
    throw new ApiError((data && data.erro) || `Erro ${response.status}.`, response.status);
  }
  return data;
}

export function withToken(path) {
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}t=${encodeURIComponent(TOKEN)}`;
}

export function reportUrl(scanId, format, download = false) {
  const base = `/api/resultados/${encodeURIComponent(scanId)}/relatorio.${format}`;
  return withToken(download ? `${base}?baixar=1` : base);
}

export function jobEvents(jobId, onEvent, onEnd) {
  const source = new EventSource(withToken(`/api/auditorias/${encodeURIComponent(jobId)}/eventos`));
  source.onmessage = (message) => {
    try {
      onEvent(JSON.parse(message.data));
    } catch {
      /* evento malformado: ignora */
    }
  };
  source.addEventListener("fim", () => {
    source.close();
    onEnd?.();
  });
  return source;
}
