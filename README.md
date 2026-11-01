# OFF ANGELL

Ferramenta educacional e defensiva em Python para descoberta de portas TCP e análise de serviços com Nmap, coleta de banners, NSE, Nikto e ZAP Automation Framework. Interface de terminal em português, com o banner e as cores originais do projeto.

Desenvolvida para máquinas próprias, laboratórios, CTFs e sistemas com autorização explícita. As análises NSE, Nikto e ZAP dependem de uma escolha no menu da porta; abrir o programa não inicia nenhuma varredura.

## Visão geral

```text
============================================================
[ MENU PRINCIPAL ]
============================================================
Scanner defensivo para ambientes próprios ou autorizados.

[1] Iniciar scan
[2] Verificar dependências
[3] Visualizar relatórios
[4] Ajuda
[5] Sair
[6] Scan de segurança web (URL)
[7] Configurações do Nuclei
[8] Website Security Scanner
[9] Teste de carga HTTP controlado
```

Exemplo ilustrativo após uma varredura:

```text
[ PORTAS ABERTAS ]
Alvo: localhost | Endereço: 127.0.0.1

[0] 22/tcp     OPEN  ssh            OpenSSH 9.x
[1] 80/tcp     OPEN  http           Apache httpd 2.4.x
[2] 443/tcp    OPEN  https          nginx 1.x

[r] Salvar relatório antes de sair | [s] Voltar ao menu principal
```

Digite o **índice entre colchetes**: `2` seleciona a porta `443` nesse exemplo. Índices inexistentes são rejeitados.

## Funcionalidades

- Scan rápido das 100 portas TCP mais comuns, completo (`1-65535`) ou personalizado.
- Conexão TCP explícita (`-sT`) e detecção de serviços/versões (`-sV`) nos três modos.
- Validação de um único IP IPv4/IPv6 ou hostname e de listas/intervalos de portas.
- Portas abertas ordenadas, com serviço, produto, versão e informações complementares.
- Banner HTTP por `HEAD /`; HTTPS com TLS e validação de certificado; leitura passiva nos demais serviços.
- Localização das ferramentas no `PATH` e em caminhos conhecidos de Windows/Linux.
- Verificação de dependências sem iniciar scanners.
- Scan web explícito com URL completa, preservando esquema, porta e caminho.
- Integração opcional com Nuclei usando uma allowlist local de templates conservadores.
- Relatórios locais TXT/JSON e leitura pelo menu principal.
- Tratamento de dependências ausentes, DNS, permissões, timeout e cancelamento.

## Requisitos

| Dependência | Finalidade |
| --- | --- |
| Python 3.10 ou superior, com `pip` e `venv` | Executar o programa |
| Nmap instalado no sistema | Scanner TCP e análise NSE |
| `python-nmap` | Interpretar os resultados XML do Nmap |
| `colorama` | Cores e compatibilidade do terminal; há fallback sem cores |
| Nikto e, para scripts `.pl`, Perl | Integração web opcional |
| ZAP Desktop, Automation Framework e Java | Integracao web opcional |
| Nuclei para Windows e templates oficiais | Verificações web por templates YAML, opcional |
| `PyYAML` | Inspeção segura dos templates antes da execução |
| `pytest` | Apenas desenvolvimento e testes |

`requirements.txt` instala `python-nmap`, `colorama` e PyYAML. Os executáveis externos são instalados separadamente. A ausência de Nikto/ZAP/Nuclei não impede os demais fluxos; mesmo sem Nmap, os menus de ajuda, dependências e relatórios continuam disponíveis. PyYAML lê os templates selecionados sem executar conteúdo YAML.

## Instalação

Clone o repositório, ou baixe e extraia o ZIP pelo GitHub:

```sh
git clone https://github.com/trasheexe/offangell.git
cd offangell
```

### Windows 10/11 — PowerShell

Instale Python e o [Nmap para Windows](https://nmap.org/download.html), incluindo os componentes exigidos pelo instalador, como Npcap. Na pasta do projeto:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe offangell.py
```

Se `py` não estiver disponível, use `python -m venv .venv` com Python 3.10+. A ativação do ambiente virtual não é necessária.

Além do `PATH`, o Nmap é procurado em:

```text
C:\Program Files\Nmap\nmap.exe
C:\Program Files (x86)\Nmap\nmap.exe
```

### Caminhos centralizados das ferramentas

No Windows, o OFF ANGELL procura primeiro os caminhos salvos em `%USERPROFILE%\.offangell\settings.json`, depois nomes conhecidos em `C:\Tools` (busca recursiva limitada a cinco níveis), instalações conhecidas e por último o `PATH`. Os caminhos personalizados ficam no objeto `tools`, por exemplo:

```json
{
  "tools": {
    "nmap": "C:\\Tools\\Nmap\\nmap.exe",
    "nuclei": "C:\\Tools\\Nuclei\\nuclei.exe",
    "zap": "C:\\Tools\\ZAP\\Zed Attack Proxy\\ZAP.exe",
    "zap_launcher": "C:\\Tools\\ZAP\\Zed Attack Proxy\\zap.bat",
    "nikto": "C:\\Tools\\nikto-2.6.1\\program\\nikto.pl",
    "java": "",
    "perl": "",
    "powershell": "",
    "metasploit": ""
  }
}
```

O diagnostico informa os caminhos encontrados para ZAP Desktop e ZAP Automation Framework separadamente. A instalacao nao exige `zap-baseline.py`. Nikto em `.pl` requer Perl; quando o script existe sem Perl, o terminal mostra um aviso e os outros scanners continuam.

### Linux

Instale Python, suporte a `venv`/`pip` e Nmap pelo gerenciador da distribuição ou pelo [instalador oficial do Nmap](https://nmap.org/download.html). Na pasta do projeto:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python offangell.py
```

O Nmap também é procurado em `/usr/bin/nmap` e `/usr/local/bin/nmap`.

Nas próximas execuções, repita apenas o último comando do seu sistema. Se uma ferramenta estiver em outro diretório, inclua-o no `PATH` ou ajuste as constantes de caminhos em `core/tools.py`.

### Nuclei — opcional

Baixe o binário Windows na [página oficial de releases do Nuclei](https://github.com/projectdiscovery/nuclei/releases), extraia `nuclei.exe` e adicione sua pasta ao `PATH`. Também é possível abrir **Configurações do Nuclei** no menu `[7]` e informar o caminho completo do executável. O [guia oficial de instalação](https://docs.projectdiscovery.io/opensource/nuclei/install) recomenda baixar o binário correspondente ao sistema e extraí-lo.

Confirme a instalação no PowerShell:

```powershell
nuclei.exe -version
```

Como alternativa, instale via Go (Go atualizado é necessário):

```powershell
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

O Nuclei não baixa nem atualiza templates durante um scan. Se os templates não estiverem instalados, use **Configurações do Nuclei → Atualizar templates manualmente** e confirme a ação. O comando oficial é `nuclei -update-templates`; para um diretório personalizado, o OFF ANGELL usa `-update-template-dir`. Confira os caminhos `-update-templates` e de armazenamento na [documentação oficial](https://docs.projectdiscovery.io/opensource/nuclei/running).

## Como usar

1. No menu principal, escolha **Verificar dependências** para conferir a instalação.
2. Escolha **Iniciar scan** e informe um alvo, como `127.0.0.1`, `::1`, `localhost` ou `meuservidor.local`.
3. Selecione scan rápido, completo ou personalizado. Exemplos de portas: `1-1000`, `80,443,8080` e `22,80-90`.
4. Aguarde o resultado e selecione o índice da porta desejada.
5. Escolha explicitamente a análise no menu da porta.
6. Salve o relatório antes de deixar a sessão: opção `6` no menu da porta ou `r` na lista de portas.

Para verificar um site, escolha **Website Security Scanner** (`[8]`) e informe um único endereço `http://` ou `https://`. Confirme que possui autorização antes de iniciar. O caminho e a porta informados são mantidos no alvo. DNS/conectividade são verificados antes das ferramentas; somente a porta especificada (ou a padrão do protocolo) é consultada. Um redirecionamento para outro hostname ou porta bloqueia os scanners. A ação consulta informações HTTP, executa OWASP ZAP Automation Framework, Nikto e Nuclei quando habilitado/instalado e gera relatórios TXT e JSON automaticamente. O Nuclei recebe a URL original e não segue redirecionamentos.

A opcao `[9]` faz um teste de disponibilidade HTTP controlado no URL autorizado. Ela envia somente requisicoes `HEAD`, uma por segundo, em sequencia; permite duracao de 1 a 30 segundos, limita o total a 30 requisicoes, nao segue redirecionamentos e exige confirmacao antes de enviar. Registra codigos HTTP, erros e latencia media em relatorios TXT e JSON. Nao e um DDoS nem confirma vulnerabilidades.

Não são aceitos URLs completos, credenciais, portas anexadas ao hostname, redes CIDR, listas de alvos, curingas, opções de linha de comando ou caracteres de controle. IPv6 deve ser informado sem colchetes e sem identificador de interface (`%`). Um hostname com vários endereços usa apenas um endereço para o Nmap, preferindo IPv4; o endereço analisado aparece na tela e no relatório.

```text
Alvo: localhost
Porta: 443
Serviço: https

[1] Informações do serviço
[2] Banner
[3] Análise NSE
[4] Nikto
[5] ZAP Automation Framework
[6] Salvar relatório
[7] Voltar
[8] Sair
```

As opções Nikto/ZAP só são liberadas para serviços identificados como web. Se o serviço for desconhecido, as portas `80`, `443`, `8080` e `8443` servem como referência. HTTPS é escolhido para `443`/`8443`, nomes de serviço HTTPS/SSL ou túnel SSL informado pelo Nmap.

`Ctrl+C` durante uma análise cancela a operação e mantém a sessão para salvar resultados já coletados. Nos menus, encerra o programa. `s` na lista volta ao menu principal; `8` no menu da porta encerra a aplicação. Os resultados em memória não são salvos automaticamente.

## O que cada ferramenta faz

| Recurso | Comportamento no OFF ANGELL |
| --- | --- |
| Nmap | Descobre portas TCP e identifica serviços/versões, sem análise de vulnerabilidades automática |
| Banner | Envia uma requisição HTTP HEAD em serviços web; nos demais, aguarda dados sem enviar comandos |
| NSE | Executa a seleção defensiva de scripts na porta escolhida e apresenta os resultados como indícios |
| Nikto | Verifica configuração e identificação de software web, com perfil limitado |
| ZAP Automation Framework | Executa spider, aguarda passive scan e exporta alertas; nao executa active scan |
| Nuclei | Executa somente templates HTTP revisados e allowlisted; não faz fuzzing, brute force, DoS, OAST, headless ou testes por protocolo de arquivo |

### NSE

O filtro usado é:

```text
(vuln and safe) and not (auth or brute or dos or exploit or intrusive or fuzzer or external or broadcast or malware)
```

Isso restringe a antiga seleção ampla `vuln`. Os [critérios das categorias são definidos pelo Nmap](https://nmap.org/book/nse-usage.html). O programa mostra os scripts que retornaram resultados, inclusive resultados de host, sem afirmar que uma vulnerabilidade foi confirmada. Ausência de resultados não comprova ausência de problemas.

### Nikto — opcional

Instale o [Nikto oficial](https://github.com/sullo/nikto). A busca usa `NIKTO_PATHS`, incluindo caminhos comuns de instalacao e `nikto.pl`. Scripts Perl usam um interpretador encontrado por `PERL_PATHS`, incluindo Strawberry Perl no Windows. Configure `PERL_PATH`, `NIKTO_PATH`, `NIKTO_TIMEOUT` e `NIKTO_ENABLED` em `.env` ou no ambiente do processo. Para diagnostico de modulos/TLS e testes locais em `127.0.0.1`, consulte [docs/NIKTO_SETUP.md](docs/NIKTO_SETUP.md) e execute `python tools/setup_nikto.py`.

A chamada usa uma lista de argumentos, URL HTTP/HTTPS, `-Tuning 2b`, `-Plugins headers;tests` e `-nointeractive`. O perfil limita os testes a configuração/arquivos padrão e identificação de software, conforme a [documentação de tuning](https://github.com/sullo/nikto/wiki/Scan-Tuning) e de [seleção de plugins](https://github.com/sullo/nikto/wiki/Selecting-Plugins).

### OWASP ZAP Automation Framework - opcional

A integracao usa o ZAP Desktop instalado e localiza `zap.bat` (Windows) ou `zap.sh` (Linux/macOS) junto a aplicacao. No Windows chama esse script com `-cmd -autorun <plano.yaml>`; nunca passa argumentos diretamente a `ZAP.exe`. Sem script de inicializacao, procura um JAR de inicializacao e o executa com Java. `zap-baseline.py` nao e necessario.

Cada execucao cria um diretorio temporario separado e um plano YAML com a URL autorizada. O plano executa Spider, aguarda passive scan, exporta relatorio JSON e encerra o ZAP. Active Scan nao e habilitado. `stdout` e `stderr` sao capturados, limitados e sanitizados. Os codigos oficiais sao 0 (sem erros/warnings), 1 (erros) e 2 (warnings); os codigos ficam no resultado para revisao.

O relatorio JSON e convertido em alertas marcados como indicios, sujeitos a validacao manual. O diretorio temporario e removido ao final. O diagnostico mostra separadamente ZAP e a disponibilidade do mecanismo de automacao/Java.

Redirecionamentos de resposta para outro hostname ou porta são bloqueados na verificação inicial e impedem que os scanners iniciem. Os relatórios filtram cookies e campos comuns de segredo, mas devem ser revisados antes de compartilhar.

### Nuclei — opcional

O Nuclei é um scanner que usa templates YAML para procurar vulnerabilidades conhecidas e configurações expostas. No OFF ANGELL, ele complementa ZAP e Nikto; não substitui essas ferramentas. A documentação do projeto descreve essa abordagem baseada em templates [na visão geral oficial](https://docs.projectdiscovery.io/opensource/nuclei/overview).

O perfil padrão permite apenas os IDs `http-missing-security-headers` e `tech-detect`. Antes de cada execução, o OFF ANGELL abre os arquivos YAML com PyYAML, exige exatamente uma requisição HTTP `GET` ou `HEAD` para `{{BaseURL}}`, rejeita chaves de protocolos ou recursos ativos não permitidos e exige IDs únicos dentro do diretório. Tags e exclusões adicionais são aplicadas como defesa em profundidade. A assinatura dos templates também é verificada pelo Nuclei com `-disable-unsigned-templates`; se nenhum template permitido assinado estiver disponível, o scan será marcado como indisponível.

O comando é criado com `-rate-limit 2 -concurrency 2 -bulk-size 1 -timeout 8 -retries 1 -max-host-error 5 -no-interactsh -disable-unsigned-templates -disable-redirects -omit-raw`. A ajuda (`nuclei -h`) da versão instalada é conferida antes do scan; se faltar uma opção necessária, o OFF ANGELL não executa o comando. A saída JSONL é lida linha por linha. Request e response não são gravados. `-as`, workflows, templates headless, file, código, fuzzing e módulos de força bruta/DoS não são habilitados.

O menu `[7] Configurações do Nuclei` permite ativar/desativar a ferramenta, configurar executável, pasta de templates, timeout global (até 600 s), limite (até 5 requisições/s) e concorrência (até 2). O arquivo é salvo em `%USERPROFILE%\\.offangell\\settings.json`. Atualizações exigem ação separada e confirmação; scans não atualizam templates automaticamente.

Os achados aparecem na seção `nuclei_findings` dos relatórios TXT/JSON e são mantidos separados dos estados de ZAP/Nikto, para revisão e correlação manual. Severidade é a classificação do template e indica um possível problema; não prova exploração. `extracted_results` pode conter conteúdo de resposta e é filtrado para valores sensíveis comuns. Templates são mantidos pela comunidade e podem ter falsos positivos, falsos negativos, mudança de cobertura ou assinatura ausente. O diretório configurado só fornece arquivos à allowlist; ele não pode adicionar templates arbitrários ao perfil padrão.

O repositório não inclui um runner Metasploit. Nenhum módulo Metasploit é iniciado pelo fluxo web; uma futura integração deve limitar-se a módulos auxiliares previamente revisados.

## Relatórios

Os relatórios são salvos em `reports/`, relativo à pasta do projeto, com nomes seguros e únicos:

```text
reports/scan_127.0.0.1_2026-10-05_182000_123456_a1b2c3d4.json
```

TXT e JSON registram data/hora com fuso do sistema, alvo, URL web original quando utilizada, endereço analisado, modo, estado da varredura, portas, produtos/versões, banners, resultados NSE, achados Nuclei e estados das ferramentas opcionais. JSON inclui também metadados estruturados de início, conclusão e salvamento quando disponíveis. Falhas e cancelamentos podem ser salvos.

O programa remove caracteres de controle e mascara campos comuns de senha, token, autenticação e cookies. A saída de Nikto/ZAP é limitada a 64 KiB, sanitizada e registrada no relatório; o JSON completo do ZAP usado para extrair alertas fica temporário e é removido após a execução. Revise relatórios antes de compartilhá-los; a filtragem não identifica todo possível dado sensível de um serviço.

Os relatórios locais são ignorados pelo Git, exceto `reports/.gitkeep`. O limite por arquivo é de 2 MB. A opção **Visualizar relatórios** lista e abre os TXT/JSON salvos.

## Limites e solução de problemas

- Apenas TCP e um alvo por sessão; sem varredura UDP ou processamento de listas de hosts.
- Nmap: limite de 30 minutos por operação; cada script NSE tem limite de 60 segundos.
- Banner: timeout de conexão de 5 segundos e janela de leitura de até 5 segundos, limitada a 8 KiB. Para HTTP, somente os cabeçalhos são retidos.
- Nikto/ZAP: limite externo de 10 minutos. Cancelamentos e timeouts encerram o processo iniciado e solicitam o encerramento da sua árvore local.
- Serviços não web que exigem negociação prévia podem não fornecer banner. TLS não é desabilitado para aceitar certificados inválidos.

| Situação | Como resolver |
| --- | --- |
| `python-nmap` ausente | Execute `-m pip install -r requirements.txt` com o Python do ambiente virtual |
| Nmap não encontrado | Confira a instalação, o `PATH` e `NMAP_PATHS` em `core/tools.py` |
| DNS não resolvido | Confira o hostname e a conexão; tente o IP conhecido do laboratório |
| Alvo sem resposta | Verifique endereço, conectividade e regras da rede; não significa necessariamente que a máquina está desligada |
| Nenhuma porta aberta | O alvo respondeu, mas nenhuma porta aberta foi registrada no intervalo escolhido; tente outro modo autorizado |
| Índice inválido | Digite o número entre colchetes, começando em zero |
| Timeout | Confira o serviço ou utilize um intervalo menor de portas |
| Permissão insuficiente | Confira permissões de execução, acesso a `reports/` e a instalação do Npcap no Windows |
| Nikto ausente | Instale Nikto; scripts `.pl` também precisam de Perl |
| ZAP Automation Framework indisponivel | Confira `zap.bat`/`zap.sh`, o JAR de inicializacao e Java; as demais ferramentas continuam disponiveis |
| Nuclei ausente/incompatível | Instale o binário oficial, configure o caminho e use uma versão com as opções do perfil seguro |
| Templates Nuclei ausentes | Use a atualização manual em Configurações do Nuclei e confirme a ação |
| Nenhum template permitido | Verifique a versão/assinatura e se o diretório tem os IDs da allowlist do OFF ANGELL |
| Certificado TLS inválido | Configure a CA do laboratório e use um hostname correspondente ao certificado |

## Estrutura

```text
offangell/
├── offangell.py              # Banner, menus e interação em português
├── core/
│   ├── __init__.py
│   ├── scanner.py           # Nmap, NSE, DNS e banners
│   ├── tools.py             # Dependências, Nikto, ZAP e subprocessos
│   ├── nuclei.py            # Política, execução, JSONL e templates Nuclei
│   ├── web.py               # Fluxo por URL para ZAP, Nikto e Nuclei
│   ├── config.py            # Configurações locais do Nuclei
│   ├── validation.py        # Alvos, portas e URLs
│   └── reports.py           # Relatórios e filtragem de campos sensíveis
├── tests/                   # Testes isolados com mocks
├── reports/.gitkeep
├── .github/workflows/tests.yml
├── requirements.txt
├── requirements-dev.txt
├── .gitignore
└── README.md
```

## Testes e desenvolvimento

**PowerShell:**

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m compileall -q offangell.py core tests
.\.venv\Scripts\python.exe -m pytest -q
```

**Linux:**

```bash
./.venv/bin/python -m pip install -r requirements-dev.txt
./.venv/bin/python -m compileall -q offangell.py core tests
./.venv/bin/python -m pytest -q
```

Os testes usam mocks para Nmap, DNS, sockets e subprocessos. Uma fixture bloqueia as chamadas reais de rede/processos usadas pela aplicação; não é necessário instalar Nmap, Nikto, ZAP ou Nuclei para executar a suíte. Ela cobre validação de URLs, localização de ferramentas, política e inspeção YAML, JSONL válido/inválido, timeouts, atualizações confirmadas, relatórios, TLS, tratamento de erros e menus.

O workflow do GitHub Actions está configurado para Windows e Linux com Python 3.10 e 3.13. Nenhum scanner é executado pelo CI.
