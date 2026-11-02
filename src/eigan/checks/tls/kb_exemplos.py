"""Exemplos de correção compartilhados pelas entradas de TLS da base de conhecimento.

Os exemplos de versões e cifras seguem o perfil "Intermediate" das diretrizes da Mozilla,
versão 6.0 (https://ssl-config.mozilla.org/guidelines/6.0.json): só TLS 1.2 e 1.3 e, no
TLS 1.2, apenas ECDHE com AES-GCM ou ChaCha20-Poly1305. A sintaxe de cada servidor foi
conferida na documentação oficial (nginx, Apache mod_ssl, Tomcat, Node.js, Microsoft Learn).
"""

from __future__ import annotations

from ...core.kb import Fix

MOZILLA_TLS12_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
)

MOZILLA_GUIDELINES = "https://ssl-config.mozilla.org/guidelines/6.0.json"
OWASP_TLS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
)
MS_SCHANNEL = "https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings"
MS_DISABLE_SUITE = "https://learn.microsoft.com/en-us/powershell/module/tls/disable-tlsciphersuite"
SSL_LABS_GUIDE = "https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide"
NGINX_SSL = "https://nginx.org/en/docs/http/ngx_http_ssl_module.html"
APACHE_SSL = "https://httpd.apache.org/docs/2.4/mod/mod_ssl.html"
LETSENCRYPT_GUIDE = "https://letsencrypt.org/docs/integration-guide/"
LETSENCRYPT_START = "https://letsencrypt.org/pt-br/getting-started/"
CABF_BR = "https://cabforum.org/working-groups/server/baseline-requirements/requirements/"

MODERN_NGINX = Fix(
    "nginx",
    "nginx",
    "ssl_protocols TLSv1.2 TLSv1.3;\n"
    f"ssl_ciphers {MOZILLA_TLS12_CIPHERS};\n"
    "ssl_prefer_server_ciphers off;",
    "nginx",
)
MODERN_APACHE = Fix(
    "apache",
    "Apache (mod_ssl)",
    "SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
    f"SSLCipherSuite {MOZILLA_TLS12_CIPHERS}\n"
    "SSLHonorCipherOrder off",
    "apache",
)
MODERN_TOMCAT = Fix(
    "tomcat",
    "Tomcat (server.xml)",
    '<SSLHostConfig protocols="TLSv1.2,TLSv1.3"\n'
    f'               ciphers="{MOZILLA_TLS12_CIPHERS}">\n'
    '  <Certificate certificateFile="conf/cert.pem" certificateKeyFile="conf/key.pem" />\n'
    "</SSLHostConfig>",
    "xml",
)
MODERN_NODE = Fix(
    "express",
    "Node.js (https)",
    "https.createServer({\n"
    "  key: fs.readFileSync('privkey.pem'),\n"
    "  cert: fs.readFileSync('fullchain.pem'),\n"
    "  minVersion: 'TLSv1.2',\n"
    f"  ciphers: '{MOZILLA_TLS12_CIPHERS}',\n"
    "}, app).listen(443);",
    "javascript",
)
#: A Microsoft documenta só o valor ``Enabled`` e avisa que pode ser preciso reiniciar o serviço.
#: ``Test-Path`` antes de criar: ``New-Item -Force`` sobre uma chave existente apagaria os valores.
SCHANNEL_LEGACY_OFF = Fix(
    "iis",
    "IIS / Windows (PowerShell como administrador)",
    "# ATENÇÃO: no Windows Server 2008 R2 e anteriores o TLS 1.2 vem desligado. Ative-o ANTES\n"
    "# (Enabled=1 em 'TLS 1.2\\Server') ou o servidor ficará sem nenhum protocolo utilizável.\n"
    "$base = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols'\n"
    "foreach ($versao in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {\n"
    '    $chave = "$base\\$versao\\Server"\n'
    "    if (-not (Test-Path $chave)) { New-Item -Path $chave -Force | Out-Null }\n"
    "    New-ItemProperty -Path $chave -Name 'Enabled' -Value 0 -PropertyType DWord -Force | Out-Null\n"
    "}\n"
    "# As aplicações precisam abrir novas credenciais TLS: reinicie o serviço (ou a máquina)\n"
    "iisreset",
    "powershell",
)
SCHANNEL_WEAK_SUITES_OFF = Fix(
    "iis",
    "IIS / Windows (PowerShell como administrador)",
    "Get-TlsCipherSuite |\n"
    "    Where-Object { $_.Name -match 'NULL|anon|EXPORT|RC4|RC2|IDEA|DES' } |\n"
    "    ForEach-Object { Disable-TlsCipherSuite -Name $_.Name }\n"
    "# Confira o que sobrou (a Microsoft informa que não é preciso reiniciar)\n"
    "Get-TlsCipherSuite | Select-Object Name",
    "powershell",
)

#: exemplos para aceitar só as versões e cifras modernas
MODERN_TLS: tuple[Fix, ...] = (
    MODERN_NGINX,
    MODERN_APACHE,
    SCHANNEL_LEGACY_OFF,
    MODERN_TOMCAT,
    MODERN_NODE,
)
#: exemplos para remover as cifras fracas
STRONG_CIPHERS: tuple[Fix, ...] = (
    MODERN_NGINX,
    MODERN_APACHE,
    SCHANNEL_WEAK_SUITES_OFF,
    MODERN_TOMCAT,
    MODERN_NODE,
)

CERT_NGINX = Fix(
    "nginx",
    "nginx",
    "ssl_certificate     /etc/letsencrypt/live/exemplo.com.br/fullchain.pem;\n"
    "ssl_certificate_key /etc/letsencrypt/live/exemplo.com.br/privkey.pem;",
    "nginx",
)
CERT_APACHE = Fix(
    "apache",
    "Apache (mod_ssl 2.4.8 ou mais novo)",
    "SSLCertificateFile    /etc/letsencrypt/live/exemplo.com.br/fullchain.pem\n"
    "SSLCertificateKeyFile /etc/letsencrypt/live/exemplo.com.br/privkey.pem",
    "apache",
)
CERT_IIS = Fix(
    "iis",
    "IIS (PowerShell como administrador)",
    "# Depois de importar o novo certificado em Cert:\\LocalMachine\\My, informe a impressão digital\n"
    "Import-Module WebAdministration\n"
    "$binding = Get-WebBinding -Name 'Default Web Site' -Protocol 'https'\n"
    "$binding.AddSslCertificate('IMPRESSAO_DIGITAL_DO_NOVO_CERTIFICADO', 'my')",
    "powershell",
)
CERT_CERTBOT = Fix(
    "linux",
    "Let's Encrypt (certbot)",
    "sudo certbot --nginx -d exemplo.com.br -d www.exemplo.com.br\n"
    "# confere se a renovação automática funciona\n"
    "sudo certbot renew --dry-run",
    "bash",
)
