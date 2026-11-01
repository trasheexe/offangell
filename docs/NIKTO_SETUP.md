# Configuracao e diagnostico do Nikto

O OFF ANGELL localiza Nikto e Perl pela configuracao do usuario, pela arvore `C:\tools` (busca recursiva limitada) e, por fim, pelo `PATH`. Em outras plataformas, a busca por comandos Unix e diretorios comuns continua ativa.

## Caminhos e `.env`

Os valores padrao e o arquivo de configuracao do OFF ANGELL continuam em `core/config.py` e `~/.offangell/settings.json`. Para substituir caminhos sem editar o codigo, crie `.env` na raiz do repositorio:

```env
PERL_PATH=C:\tools\perl\bin\perl.exe
NIKTO_PATH=C:\tools\nikto-main\program\nikto.pl
NIKTO_TIMEOUT=600
NIKTO_ENABLED=true
```

As variaveis de ambiente do processo prevalecem sobre `.env`. O OFF ANGELL nao sobrescreve o `.env`. `NIKTO_TIMEOUT` aceita de 1 a 1800 segundos. `NIKTO_ENABLED` aceita `true/false`, `yes/no`, `on/off` ou `1/0`.

Nikto `.pl` e executado como argumentos separados `[perl.exe, nikto.pl, ...]`, sem `shell=True`. Scripts `.bat` e `.cmd` passam pelo `cmd.exe` com metacaracteres rejeitados. O OFF ANGELL acrescenta diretorios de runtime em `C:\tools` ao `PATH` do subprocesso Perl, sem mudar o `PATH` global. No Windows, LibWhisker 2.5 tem uma falha de conexao TCP nao bloqueante com este Perl; o OFF ANGELL executa uma copia temporaria da pasta `program`, muda somente essa opcao nessa copia e preserva a instalacao original. Saida e erros sao capturados, limitados e sanitizados. Timeouts encerram a arvore local do processo. Falhas de conexao nao sao apresentadas como achados positivos.

## Diagnostico

Na raiz do repositorio:

```powershell
python tools/setup_nikto.py
python tools/setup_nikto.py --report reports/nikto-diagnostic.json
```

O script testa execucao e versao do Perl e Nikto; importa `XML::Writer`, `Net::SSLeay`, `IO::Socket::SSL`, `Net::SSL` e modulos principais; procura configuracoes do Nikto; verifica arquitetura x64, DLLs OpenSSL, Make e compilador. Um caminho encontrado nao conta como instalado sem teste real de execucao/importacao. O diagnostico nao baixa nem instala nada por padrao.

Para testar Nikto, execute a varredura apenas contra servidores locais temporarios em `127.0.0.1`:

```powershell
python tools/setup_nikto.py --local-test --report reports/nikto-local-test.json
```

O teste inicia um servidor HTTP e, quando TLS esta disponivel, cria um certificado autoassinado efemero com OpenSSL em uma pasta temporaria, executa Nikto em HTTPS e apaga chave/certificado ao terminar. Tambem e possivel fornecer seu proprio certificado e chave PEM:

```powershell
python tools/setup_nikto.py --https-cert .\certs\localhost.crt --https-key .\certs\localhost.key
```

O teste HTTPS so passa quando os modulos TLS carregam, Nikto termina e o servidor local registra requisicoes TLS. Se nao houver OpenSSL, o diagnostico explica que o teste esta pendente; se os modulos nao carregarem, explica a dependencia ausente.

## Dependencias Perl e TLS

A opcao abaixo instala `Net::SSLeay` e `IO::Socket::SSL` somente quando nao puderem ser importados. Ela usa o mirror HTTPS oficial `https://www.cpan.org/`, requer GNU Make e compilador executaveis, preserva `XML::Writer` se ja estiver funcionando e revalida os modulos depois da tentativa:

```powershell
python tools/setup_nikto.py --install-deps
```

CPAN pode compilar extensoes XS contra as bibliotecas OpenSSL nativas do Perl. Se falhar, verifique arquitetura: Perl x64 precisa de modulos x64 compativeis e das DLLs OpenSSL/runtime da mesma distribuicao. Nao copie DLLs de sites aleatorios ou de outras arquiteturas/versoes. Se faltar toolchain ou OpenSSL compativel, use uma distribuicao Strawberry Perl x64 completa obtida do [site oficial](https://strawberryperl.com/) e defina `PERL_PATH` para esse Perl. O script nao altera o `PATH` global, Defender, exclusoes de antivirus nem instalacao Perl.

Nikto 2.6.1 usa `Net::SSLeay` ou `Net::SSL` para HTTPS. `IO::Socket::SSL` depende internamente de `Net::SSLeay`; a presenca de arquivos nao prova que TLS funcione. A validacao exige importacao dos modulos e uma conexao TLS local bem-sucedida. Consulte os [requisitos oficiais do Nikto](https://github.com/sullo/nikto/wiki/Install-Unix), o [arquivo oficial de configuracao](https://github.com/sullo/nikto/blob/main/program/nikto.conf.default) e a documentacao de [`IO::Socket::SSL`](https://metacpan.org/pod/IO::Socket::SSL).

## Integracao e limites

O menu Website Security Scanner usa a mesma resolucao de ferramentas do diagnostico e chama Nikto somente apos validar o alvo web. O perfil passa `-Tuning 2b` e os plugins `headers;tests`; nao ativa brute force ou exploracao. A bateria padrao do Nikto pode emitir milhares de requisicoes; no teste deste ambiente, foram cerca de 4.000 requisicoes, sempre apenas a `127.0.0.1`. O scanner web bloqueia redirecionamentos para fora do escopo.

Execute scans somente em sistemas proprios ou com autorizacao explicita. A suite automatizada usa mocks e nao faz chamadas de rede ou subprocessos reais.

## Estado verificado neste ambiente

Foram encontrados `C:\tools\perl\bin\perl.exe`, `C:\tools\nikto-main\program\nikto.pl`, `nikto.conf.default`, `XML::Writer`, `Net::SSLeay`, `IO::Socket::SSL`, `C:\tools\cpan\c\bin\gmake.exe`, `gcc.exe` e OpenSSL x64. Perl informou versao 5.42.3 x64; Nikto informou 2.6.1 (LibWhisker 2.5). As DLLs OpenSSL estavam fora do `PATH`; o OFF ANGELL agora as disponibiliza apenas aos processos Perl. Os testes reais locais HTTP e HTTPS passaram; Nikto confirmou TLS contra um certificado de teste autoassinado em `127.0.0.1`. Nao instalei modulos; o `PATH` global, Defender e instalacao original do Nikto nao foram alterados.
