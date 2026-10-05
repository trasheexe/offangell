# OFF ANGELL — NMAP

Scanner interativo de terminal escrito em Python para descoberta de portas e análise de serviços em ambientes próprios ou autorizados. O projeto utiliza o Nmap para identificar portas abertas e oferece um menu com coleta de banners, scripts NSE e integração com Nikto e OWASP ZAP.

## Funcionalidades

- Varredura das portas TCP de `1` a `65535`, com detecção de serviços e versões (`-sV`).
- Listagem das portas abertas, ordenadas por número, com protocolo e nome do serviço.
- Coleta de banners por conexão TCP, com timeout de 3 segundos.
- Análise da porta selecionada com Nmap NSE (`-sV --script vuln`).
- Execução opcional do Nikto e do ZAP Baseline para análise de serviços web.
- Interface em português, com cores no terminal.

## Requisitos

| Dependência | Uso | Obrigatória |
| --- | --- | --- |
| Python 3 com `pip` e `venv` | Execução do programa e instalação das bibliotecas | Sim |
| Nmap | Varredura de portas e execução de scripts NSE | Sim |
| `python-nmap` | Comunicação entre Python e Nmap | Sim |
| `colorama` | Cores no terminal | Sim |
| Comando `nikto` | Análise web pelo menu | Apenas para a opção 3 |
| Comando `zap-baseline.py` e seu ambiente de execução | ZAP Baseline pelo menu | Apenas para a opção 4 |

O pacote [`python-nmap`](https://pypi.org/project/python-nmap/) fornece o módulo `nmap` importado pelo código. O executável do Nmap precisa ser instalado separadamente.

## Instalação

### 1. Obtenha o projeto

Clone o repositório com Git ou baixe e extraia o ZIP pelo GitHub. Para clonar:

```sh
git clone https://github.com/trasheexe/NMAP.git
cd NMAP
```

### 2. Instale o Nmap

Utilize o [download oficial do Nmap](https://nmap.org/download.html) para seu sistema operacional. Se o executável estiver no `PATH`, confira a instalação com:

```sh
nmap --version
```

O programa procura o comando `nmap` no `PATH` e também tenta estes caminhos definidos em `NMAP_PATHS`:

- `C:\Program Files\Nmap\nmap.exe`
- `C:\Program Files (x86)\Nmap\nmap.exe`
- `/usr/bin/nmap`
- `/usr/local/bin/nmap`

Se a instalação estiver em outro local, adicione esse diretório ao `PATH` ou ajuste `NMAP_PATHS` em `offangell.py`.

### 3. Prepare o ambiente Python

Execute os comandos na pasta do projeto. Eles usam o Python do ambiente virtual diretamente, sem precisar ativá-lo.

**Windows — PowerShell:**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install python-nmap colorama
.\.venv\Scripts\python.exe offangell.py
```

Se o comando `py` não estiver disponível, use `python -m venv .venv`, desde que `python` execute o Python 3.

**Linux/macOS:**

```sh
python3 -m venv .venv
./.venv/bin/python -m pip install python-nmap colorama
./.venv/bin/python offangell.py
```

Nas próximas execuções, basta repetir o último comando correspondente ao seu sistema.

## Como usar

1. Inicie `offangell.py` com o Python do ambiente virtual.
2. Digite um IP ou hostname, como `127.0.0.1` para a própria máquina. Informe somente o endereço, sem `http://`, caminho ou porta.
3. Aguarde a varredura das 65.535 portas TCP.
4. Escolha o **índice entre colchetes** da porta desejada para abrir o menu OFF ANGELL.
5. Selecione uma ação no menu.

Exemplo ilustrativo de resultado:

```text
[0] Porta 22/tcp (ssh)
[1] Porta 80/tcp (http)
```

Nesse exemplo, digite `1` para selecionar a porta `80`. Embora a mensagem do programa peça o número da porta, a entrada esperada é o índice da lista.

| Opção | Ação |
| --- | --- |
| `1` | Coletar o banner do serviço na porta selecionada |
| `2` | Executar os scripts NSE da categoria `vuln` nessa porta |
| `3` | Executar `nikto -h <alvo> -p <porta>` |
| `4` | Executar `zap-baseline.py -t http://<alvo>:<porta>` |
| `5` | Voltar à lista de portas da varredura atual |
| `6` | Encerrar o programa |

Na lista de portas, digite `s` para sair. Também é possível interromper o programa com `Ctrl+C`. Para analisar outro alvo, execute o programa novamente.

## Integrações opcionais

**Nikto:** a opção 3 chama diretamente o comando `nikto`. Ele precisa estar instalado e acessível no `PATH` do processo que executa o Python. Use essa opção em portas que ofereçam um serviço web.

**OWASP ZAP:** a opção 4 chama diretamente `zap-baseline.py`. A [documentação oficial do ZAP Baseline](https://www.zaproxy.org/docs/docker/baseline-scan/) descreve o script e sua distribuição nas imagens Docker do ZAP. A integração atual não inicia um contêiner: ela exige que o script seja executável pelo sistema e que seu ambiente esteja configurado. Ter apenas a interface gráfica do ZAP instalada não garante esse requisito; para usar Docker, é necessário adaptar `run_zap()`.

As constantes `NIKTO_PATHS` e `ZAP_PATHS` estão declaradas no código, mas não são utilizadas pelas funções de execução. Alterá-las não muda os comandos chamados pelo menu.

## Comportamento atual

- A varredura inicial cobre TCP; não há opção de varredura UDP no menu.
- O intervalo de portas é fixo e a varredura completa pode demorar.
- O programa utiliza somente o primeiro host retornado pelo Nmap; o fluxo foi pensado para um alvo por execução.
- A coleta de banners usa um socket IPv4, envia `\r\n` e lê até 1.024 bytes. Não faz negociação TLS.
- A integração com ZAP monta uma URL `http://`, inclusive se a porta selecionada for `443`; HTTPS exige ajuste em `run_zap()`.
- Os resultados são exibidos no terminal, sem exportação automática de relatórios.

## Solução de problemas

| Mensagem ou situação | O que verificar |
| --- | --- |
| `ModuleNotFoundError: No module named 'nmap'` | Instale `python-nmap` com o mesmo interpretador usado para executar o programa. |
| `ModuleNotFoundError: No module named 'colorama'` | Instale `colorama` no ambiente virtual. |
| `Nmap não foi encontrado` | Confira a instalação do executável, o `PATH` e os caminhos em `NMAP_PATHS`. |
| Nikto não encontrado | Verifique se o comando `nikto` está acessível no `PATH`. |
| `zap-baseline.py` não encontrado | Configure o script e seu ambiente ou adapte `run_zap()` à sua instalação. |
| `Alvo offline` ou nenhuma porta aberta | Confira o endereço e a conectividade. A mensagem de alvo offline aparece quando o Nmap não retorna hosts. |
| Nenhum banner retornado | O serviço pode exigir uma requisição específica ou TLS, que a coleta simples não implementa. |

## Estrutura

```text
NMAP/
├── offangell.py   # Scanner, menu interativo e integrações
└── README.md     # Documentação do projeto
```
