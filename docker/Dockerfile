# Imagem do EIGAN para pipelines (CI/CD) e servidores sem interface gráfica.
#
#   docker build -f docker/Dockerfile -t eigan .
#   docker run --rm -v "$PWD:/alvo:ro" eigan auditar /alvo --tipo projeto
#   docker run --rm eigan auditar https://staging.seu-dominio.com.br --sim --falhar-em alta
#
# O painel web só escuta em 127.0.0.1 (por segurança), então dentro do container
# use a linha de comando. Relatórios vão para /dados (monte um volume para guardá-los).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    EIGAN_HOME=/dados

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir . && rm -rf /app/src

# Menor privilégio: não roda como root.
RUN useradd --create-home --uid 10001 eigan && mkdir -p /dados && chown eigan:eigan /dados
USER eigan
VOLUME ["/dados"]

ENTRYPOINT ["eigan"]
CMD ["--ajuda"]
