# OFF ANGELL

Ferramenta educacional e defensiva em Python para descoberta de portas TCP e análise de serviços com Nmap, coleta de banners, NSE, Nikto e ZAP Baseline. Interface de terminal em português, com o banner e as cores originais do projeto.

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
| `zap-baseline.py` e seu ambiente ZAP completo | Integração web opcional |
| `pytest` | Apenas desenvolvimento e testes |

`requirements.txt` contém apenas `python-nmap` e `colorama`. Os executáveis externos são instalados separadamente. A ausência de Nikto/ZAP não impede o scanner; mesmo sem Nmap, os menus de ajuda, dependências e relatórios continuam disponíveis.

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

### Linux

Instale Python, suporte a `venv`/`pip` e Nmap pelo gerenciador da distribuição ou pelo [instalador oficial do Nmap](https://nmap.org/download.html). Na pasta do projeto:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python offangell.py
```

O Nmap também é procurado em `/usr/bin/nmap` e `/usr/local/bin/nmap`.

Nas próximas execuções, repita apenas o último comando do seu sistema. Se uma ferramenta estiver em outro diretório, inclua-o no `PATH` ou ajuste as constantes de caminhos em `core/tools.py`.

## Como usar

1. No menu principal, escolha **Verificar dependências** para conferir a instalação.
2. Escolha **Iniciar scan** e informe um alvo, como `127.0.0.1`, `::1`, `localhost` ou `meuservidor.local`.
3. Selecione scan rápido, completo ou personalizado. Exemplos de portas: `1-1000`, `80,443,8080` e `22,80-90`.
4. Aguarde o resultado e selecione o índice da porta desejada.
5. Escolha explicitamente a análise no menu da porta.
6. Salve o relatório antes de deixar a sessão: opção `6` no menu da porta ou `r` na lista de portas.

Não são aceitos URLs completos, credenciais, portas anexadas ao hostname, redes CIDR, listas de alvos, curingas, opções de linha de comando ou caracteres de controle. IPv6 deve ser informado sem colchetes e sem identificador de interface (`%`). Um hostname com vários endereços usa apenas um endereço para o Nmap, preferindo IPv4; o endereço analisado aparece na tela e no relatório.

```text
Alvo: localhost
Porta: 443
Serviço: https

[1] Informações do serviço
[2] Banner
[3] Análise NSE
[4] Nikto
[5] ZAP Baseline
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
| ZAP Baseline | Navega pelo serviço web e aplica análise passiva às respostas; não executa active scan |

### NSE

O filtro usado é:

```text
(vuln and safe) and not (auth or brute or dos or exploit or intrusive or fuzzer or external or broadcast or malware)
```

Isso restringe a antiga seleção ampla `vuln`. Os [critérios das categorias são definidos pelo Nmap](https://nmap.org/book/nse-usage.html). O programa mostra os scripts que retornaram resultados, inclusive resultados de host, sem afirmar que uma vulnerabilidade foi confirmada. Ausência de resultados não comprova ausência de problemas.

### Nikto — opcional

Instale o [Nikto oficial](https://github.com/sullo/nikto). A busca usa `NIKTO_PATHS`, incluindo caminhos comuns de instalação e `nikto.pl`. Scripts Perl são chamados com um interpretador localizado por `PERL_PATHS`, incluindo Strawberry Perl no Windows.

A chamada usa uma lista de argumentos, URL HTTP/HTTPS, `-Tuning 2b`, `-Plugins headers;tests` e `-nointeractive`. O perfil limita os testes a configuração/arquivos padrão e identificação de software, conforme a [documentação de tuning](https://github.com/sullo/nikto/wiki/Scan-Tuning) e de [seleção de plugins](https://github.com/sullo/nikto/wiki/Selecting-Plugins).

### ZAP Baseline — opcional

A integração procura especificamente `zap-baseline.py` em `ZAP_PATHS`. O aplicativo gráfico `zap`, `zap.sh` ou `zap.bat` não substitui esse script. A [documentação do Baseline](https://www.zaproxy.org/docs/docker/baseline-scan/) descreve o ambiente de execução e as imagens oficiais que o incluem.

O script é chamado com o Python que executa o OFF ANGELL. Portanto, seus módulos de suporte, como `zap_common.py`, e suas dependências precisam estar disponíveis nesse ambiente. Antes da análise, o programa executa somente `-h`, com limite de 10 segundos, para detectar uma instalação incompleta sem acessar o alvo.

A análise recebe `-t <URL> -m 1 -T 5`: um minuto de navegação e limites próprios do Baseline para inicialização/análise passiva. Os códigos `1` e `2` seguem a convenção de alertas do Baseline; revise a saída para interpretar os resultados. O OFF ANGELL não instala o ZAP, baixa imagens nem oferece execução Docker própria. Instalações standalone do script podem depender de Docker conforme a distribuição do ZAP; prepare esse ambiente separadamente.

## Relatórios

Os relatórios são salvos em `reports/`, relativo à pasta do projeto, com nomes seguros e únicos:

```text
reports/scan_127.0.0.1_2026-10-05_182000_123456_a1b2c3d4.json
```

TXT e JSON registram data/hora com fuso do sistema, alvo, endereço analisado, modo, estado da varredura, portas, produtos/versões, banners, resultados NSE e execuções opcionais. JSON inclui também metadados estruturados de início, conclusão e salvamento quando disponíveis. Falhas e cancelamentos podem ser salvos.

O programa remove caracteres de controle e mascara campos comuns de senha, token, autenticação e cookies. A saída completa de Nikto/ZAP aparece no terminal e não é armazenada: o relatório guarda ferramenta, porta, URL quando disponível, estado e código de saída. Revise os relatórios antes de compartilhá-los; a filtragem não identifica todo possível dado sensível de um serviço.

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
| ZAP Baseline ausente/incompleto | Configure o script, seus módulos e o ambiente ZAP; as demais funções continuam disponíveis |
| Certificado TLS inválido | Configure a CA do laboratório e use um hostname correspondente ao certificado |

## Estrutura

```text
offangell/
├── offangell.py              # Banner, menus e interação em português
├── core/
│   ├── __init__.py
│   ├── scanner.py           # Nmap, NSE, DNS e banners
│   ├── tools.py             # Dependências, Nikto, ZAP e subprocessos
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

Os testes usam mocks para Nmap, DNS, sockets e subprocessos. Uma fixture bloqueia as chamadas reais de rede/processos usadas pela aplicação; não é necessário instalar Nmap, Nikto ou ZAP para executar a suíte. Ela cobre validação, URLs, localização de ferramentas, relatórios, TLS, tratamento de erros, cancelamento e menus.

O workflow do GitHub Actions está configurado para Windows e Linux com Python 3.10 e 3.13. Nenhum scanner é executado pelo CI.
