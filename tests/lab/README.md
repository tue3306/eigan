# EIGAN Lab - laboratorio de testes reais

Servicos de verdade (e alguns simuladores rotulados) em portas altas de `127.0.0.1`, cada um em
dois modos:

- **inseguro**: configurado errado de proposito. O EIGAN **deve** reportar.
- **endurecido**: bem configurado. O EIGAN **nao deve** reportar aquelas falhas (guarda contra falso positivo).

Nada aqui e executado contra a internet, nada escuta fora de `127.0.0.1`, nada precisa de root ou
Docker. Tudo mora em `~/.eigan-lab` (fora do repositorio; mude com `EIGAN_LAB_HOME`).

## Uso rapido (Linux, WSL 2 ou runner Ubuntu do GitHub Actions)

```bash
cd tests/lab
./instalar.sh          # idempotente; baixa ~1,5 GB uma vez (micromamba, conda-forge, apt-get download, Tomcat)
./subir.sh             # sobe tudo (~15 s); aceita ids: ./subir.sh redis-inseguro nginx-endurecido
./status.sh            # tabela com o que esta no ar (--json tambem)
python verificar.py    # 141 verificacoes de que cada servico responde COMO O MODO PROMETE
./parar.sh             # para tudo (--limpar apaga dados e certificados gerados)
```

No Windows com WSL 2: `wsl -e bash -lc "cd /mnt/c/.../EIGAN/tests/lab && ./subir.sh"`. As portas TCP abertas
no WSL aparecem em `localhost` do Windows (verificado: `verificar.py` roda tambem no Windows).
**Excecoes:** UDP (DNS, memcached) nao e encaminhado pelo WSL2 em modo NAT; rode o EIGAN dentro do
WSL para esses casos. Servicos Java so sao encaminhados quando ligam em IPv4 puro (o lab ja configura isso).

Portas: `portas.env` (fonte unica). Catalogo: `catalogo.json`. Certificados: `gerar_certs.sh`
(gerados na subida, nunca versionados). Validacao: `python ferramentas/validar_catalogo.py`.

## O que existe

| Familia | Real ou simulado | Inseguro | Endurecido |
|---|---|---|---|
| nginx 18080/18443-18446/18090 | real (conda-forge) | sem cabecalhos, `.git`, `.env`, `backup.sql`, phpinfo, stub_status, listagem, CORS espelhado, cookies sem flags, TLS 1.0/1.1 com `@SECLEVEL=0`, certificados expirado / autoassinado / de outro host, SPA soft-404 | 18081 (301) e 18447: HSTS, CSP, XFO, nosniff, TLS 1.2+, AEAD, cookies seguros, dotfiles negados |
| Apache httpd 18180/18543 | real (pacote Ubuntu extraido) | server-status/info, TRACE, ServerTokens Full, ETag com inode, Indexes, TLS 1.0/1.1 | 18181/18544: Prod, TRACE off, cabecalhos, TLS 1.2+ |
| Tomcat 10.1.61 18088 + AJP 18009 | real (tarball oficial + OpenJDK) | AJP sem segredo, apps padrao, versao no erro | 18089: sem AJP, sem apps, sem versao |
| OpenSSH 10.5 12222/12223 | real (modo usuario) | KEX/cifras/MAC legados, RSA 1024, senha | so chaves, KEX/cifras modernos |
| Redis 16379/16380, memcached 21211/21212 | real | sem senha, CONFIG, UDP | requirepass, SASL, sem UDP |
| PostgreSQL 15432/15433, MySQL 13306/13307, MongoDB 27018/27019, etcd 12379/12381 | real | trust / root sem senha / noauth / HTTP puro | scram+TLS / senha+TLS obrigatorio / `--auth` / mTLS |
| FTP 12121/12122 (pyftpdlib), SMB 14445/14446 (impacket) | real | anonimo; SMBv1 anonimo | FTPS obrigatorio; SMB2 com credencial |
| DNS BIND 9.20 15353/15354 (UDP+TCP) | real | recursao aberta, AXFR, SPF `+all`, DMARC `p=none`, sem CAA/DNSSEC, CNAME pendente | recursao off, AXFR off, SPF `-all`, DMARC reject, CAA, DKIM, MTA-STS, TLS-RPT, DNSSEC |
| MQTT Mosquitto 11883/11884 | real | anonimo | usuario + TLS |
| RDP, MSSQL, VNC, Docker API, Kubernetes API, Telnet, SMTP, Elasticsearch, WinRM | **simulado** (`simuladores/`) | sem NLA, 2012 RTM, sem senha, API aberta, anonimo, texto claro, relay, Basic em HTTP | NLA, ENCRYPT_REQ, VNC auth, mTLS, 401, STARTTLS |
| Banners (Apache 2.4.49, nginx 1.16.1, vsFTPd 2.3.4, ProFTPD 1.3.5, OpenSSH 7.2p2, Exim 4.87, MySQL 5.1.73, Redis 2.8.19) | **simulado** | so o banner, sem codigo vulneravel | - |

Alvos estaticos em `alvos/`: `projeto-vulneravel` / `projeto-limpo` (dependencias em npm, pip, Maven, Go, Ruby,
Cargo, Composer, NuGet; Dockerfile, compose, Kubernetes, Terraform; configs; codigo em 9 linguagens),
`logs/` (auth Linux, nginx/Apache, IIS W3C, eventos Windows XML e CSV; pares `-ataque` / `-benigno`, IPs RFC 5737)
e `_gerado/segredos` (tokens FALSOS com formato real, gerados em tempo de execucao com
`python ferramentas/gerar_alvos.py --segredos`, ignorados pelo git para nao acionar a protecao de push).
Nada em `alvos/` fica no git: `./subir.sh` gera o que faltar com `ferramentas/gerar_alvos.py` e
`ferramentas/gerar_logs.py`, para que dependencias antigas e codigo falho de proposito nao virem alertas
do Dependabot e do CodeQL no repositorio.

## Limites honestos

- **Simulados:** RDP, MSSQL, VNC, Docker, Kubernetes, Telnet, SMTP, Elasticsearch, WinRM e os banners
  nao sao o software real: respondem so o que um cliente ve no handshake. O vsFTPd "2.3.4" nao tem a porta dos fundos.
- **SMB:** o impacket nao desliga SMBv1 nem exige assinatura; o gemeo endurecido tem essa ressalva.
- **sshd sem root:** sem PAM, senhas nao autenticam; so o que o servidor anuncia (KEX, cifras, MAC, chaves, metodos) e testavel.
  `PermitRootLogin` e afins so aparecem em auditoria de arquivo (`alvos/.../configs/sshd_config`).
- **Certificados:** emitidos por uma CA privada do lab; sem informa-la ao EIGAN, "cadeia nao confiavel" aparece em todos os TLS (tolerado).
- **Apache/BIND/memcached/Mosquitto** vem de `apt-get download` (sem root); em runners Ubuntu o `apt-get update` pode exigir `sudo`.
- **CVEs:** nenhuma CVE foi confirmada por este lab, exceto CVE-2021-41773/42013 (Apache 2.4.49/2.4.50, conferido em
  httpd.apache.org). CVE-2011-2523 (vsFTPd 2.3.4) **nao** foi verificada em fonte primaria.
- **Rede:** o laboratorio nunca liga em `0.0.0.0`; para alcance de outra maquina, use um tunel SSH, nao mude o bind.

## GitHub Actions (Ubuntu)

Veja `ci-exemplo.yml`: cache de `~/.eigan-lab`, `./instalar.sh`, `./subir.sh`, `python verificar.py`, `./parar.sh`.
