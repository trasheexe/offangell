import sys
import socket
from types import SimpleNamespace
from core.validation import (
    is_web_service,
    validate_ports,
    validate_target,
)

# Importações do seu core (mantenha as pastas core/ conforme seu projeto)
try:
    from core.config import load_config, save_config
    from core.validation import is_web_service, validate_ports, validate_target
    from core.validation import validate_web_url
    from core.reports import clean_text, list_reports, new_report, now_iso, read_report, save_report
    from core.scanner import ScanError, banner_grabbing, scan_ports, vulnerability_scan
    from core.nuclei import update_nuclei_templates
    from core.tools import dependency_status, run_nikto, run_zap
    from core.web import run_web_scan
    from core.loadtest import run_controlled_http_test
except ImportError as e:
    print(f"Erro ao importar módulos do core: {e}")
    sys.exit(1)

if sys.version_info < (3, 10):
    raise SystemExit("OFF ANGELL requer Python 3.10 ou superior.")

try:
    from colorama import Fore, init
except ImportError:
    Fore = SimpleNamespace(CYAN="", RED="", GREEN="", YELLOW="", MAGENTA="", RESET="")
    def init(**kwargs): pass

# --- FUNÇÕES DE ATAQUE ---

def brute_force_service(target: str, port: int):
    print(f"{Fore.RED}[!] Tentando Brute Force na porta {port} de {target}...")
    wordlist = ["admin", "root", "user", "123456", "password"]
    for user in wordlist:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, port))
            s.send(f"{user}\n".encode()) 
            response = s.recv(1024)
            if b"success" in response.lower() or b"welcome" in response.lower():
                print(f"{Fore.GREEN}[+] Senha encontrada: {user}")
                s.close()
                return True
            s.close()
        except:
            continue
    print(f"{Fore.YELLOW}[-] Nenhuma senha da wordlist funcionou.")
    return False

def attempt_rce(target: str, port: int):
    print(f"{Fore.RED}[!] Tentando Remote Code Execution (RCE) em {target}:{port}...")
    payloads = ["'; whoami #", "\" || whoami #", "$(whoami)", "admin' --"]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        for p in payloads:
            request = f"GET /?id={p} HTTP/1.1\r\nHost: {target}\r\n\r\n"
            s.send(request.encode())
            res = s.recv(1024)
            if b"root" in res or b"www-data" in res:
                print(f"{Fore.GREEN}[+] RCE Sucesso com payload: {p}")
                return True
        print(f"{Fore.YELLOW}[-] RCE falhou.")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {e}")

# --- UTILITÁRIOS DE INTERFACE ---

def clear_screen() -> None:
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")

def pause() -> None:
    input("\nPressione Enter para continuar...")

def print_banner() -> None:
    print(f"""
{Fore.CYAN} ██████╗ ███████╗███████╗     █████╗ ███╗   ██╗ ██████╗ ███████╗██╗     ██╗
{Fore.CYAN}██╔═══██╗██╔════╝██╔════╝    ██╔══██╗████╗  ██║██╔════╝ ██╔════╝██║     ██║
{Fore.CYAN}██║   ██║█████╗  █████╗      ███████║██╔██╗ ██║██║  ███╗█████╗  ██║     ██║
{Fore.CYAN}██║   ██║██╔══╝  ██╔══╝      ██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██║     ██║
{Fore.CYAN}╚██████╔╝██║     ██║         ██║  ██║██║ ╚████║╚██████╔╝███████╗███████╗███████╗
{Fore.CYAN} ╚═════╝ ╚═╝     ╚═╝         ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝
{Fore.RESET}
""")

def header(title: str) -> None:
    clear_screen()
    print_banner()
    print(f"{Fore.CYAN}{'=' * 60}\n{title}\n{'=' * 60}")

# --- LÓGICA DE SCAN E RELATÓRIOS ---

def show_dependencies() -> None:
    header("[ DEPENDÊNCIAS ]")
    for name, available, detail in dependency_status():
        color = Fore.GREEN if available is True else Fore.YELLOW
        marker = "OK" if available is True else "!" if available is None else "--"
        print(f"{color}[{marker}] {name}: {detail}")
    pause()

def show_help() -> None:
    header("[ AJUDA ]")
    print("OFF ANGELL: Ferramenta de testes de segurança.\nUse apenas em ambientes autorizados.")
    pause()

def choose_scan_mode() -> tuple[str, str | None] | None:
    while True:
        header("[ MODO DE SCAN ]")
        print("[1] Scan rápido\n[2] Scan completo\n[3] Personalizado\n[4] Voltar")
        choice = input("Escolha: ").strip()
        if choice == "1": return "rápido", None
        if choice == "2": return "completo", "1-65535"
        if choice == "3":
            try:
                ports = validate_ports(input("Portas: "))
                return "personalizado", ports
            except ValueError as exc:
                print(f"{Fore.RED}[!] {exc}"); pause()
        if choice == "4": return None
        print(f"{Fore.RED}[!] Opção inválida."); pause()

def save_report_menu(report: dict) -> None:
    choice = input("Salvar como [1] TXT, [2] JSON ou [3] Voltar: ").strip()
    if choice == "3": return
    if choice in {"1", "2"}:
        try:
            path = save_report(report, "txt" if choice == "1" else "json")
            print(f"{Fore.GREEN}[+] Salvo: {path}")
        except Exception as exc:
            print(f"{Fore.RED}[!] Erro: {exc}")
    pause()

def view_reports() -> None:
    while True:
        header("[ RELATÓRIOS ]")
        paths = list_reports()
        if not paths:
            print("Nenhum relatório encontrado."); pause(); return
        for i, p in enumerate(paths): print(f"[{i}] {p.name}")
        choice = input("Índice ou 'v': ").strip()
        if choice.lower() == "v": return
        if choice.isdecimal() and int(choice) < len(paths):
            print(read_report(paths[int(choice)]))
        else:
            print(f"{Fore.RED}[!] Inválido.")
        pause()

def show_service(info: dict) -> None:
    for key, label in (("port", "Porta"), ("protocol", "Protocolo"), ("service", "Serviço"), ("product", "Produto"), ("version", "Versão")):
        print(f"{label}: {clean_text(str(info.get(key) or 'desconhecido'))}")

def analyze_port(choice: str, report: dict, info: dict) -> None:
    target = report["target"]
    port = int(info["port"])
    result = None
    try:
        if choice == "2":
            result = banner_grabbing(target, port, info)
            print(result.get("banner") or result.get("message", "Sem resposta."))
        elif choice == "3":
            result = vulnerability_scan(report.get("address", target), port)
            for name, output in result.get("scripts", {}).items():
                print(f"\n[{name}]\n{output}")
        elif choice == "4":
            if not is_web_service(info):
                print(f"{Fore.YELLOW}[!] O serviço não foi identificado como web."); return
            result = run_nikto(target, port, info)
            print(result['message'])
        elif choice == "5":
            if not is_web_service(info):
                print(f"{Fore.YELLOW}[!] O serviço não foi identificado como web."); return
            result = run_zap(target, port, info)
            print(result['message'])
    except KeyboardInterrupt:
        result = {
            "port": port,
            "at": now_iso(),
            "status": "cancelado",
            "message": "Análise cancelada com Ctrl+C.",
        }
        print(f"{Fore.YELLOW}[!] {result['message']}")
    except Exception as exc:
        print(f"{Fore.RED}[!] Erro: {exc}")
    if result:
        key = {"2": "banners", "3": "nse", "4": "tools", "5": "tools"}.get(choice)
        if key:
            report.setdefault(key, []).append(result)

def off_angel_menu(report: dict, info: dict) -> bool:
    while True:
        header("[ OFF ANGELL - PORTA ]")
        print(f"Alvo: {report['target']}\nPorta: {info['port']}\nServiço: {info['service']}")
        print("[1] Info [2] Banner [3] NSE [4] Nikto [5] ZAP [6] Salvar [7] Voltar [8] Sair")
        choice = input("Escolha: ").strip()
        if choice == "7": return False
        if choice == "8": return True
        if choice == "6": save_report_menu(report)
        elif choice == "1": show_service(info)
        elif choice in {"2", "3", "4", "5"}: analyze_port(choice, report, info)
        else: print(f"{Fore.RED}[!] Inválido.")
        pause()

def ports_menu(report: dict) -> bool:
    while True:
        header("[ PORTAS ABERTAS ]")
        print(f"Alvo: {report['target']}\n")
        if not report["open_ports"]:
            print("Nenhuma porta aberta.")
        for i, info in enumerate(report["open_ports"]):
            print(f"{Fore.CYAN}[{i}] {info['port']}/{info['protocol']} OPEN {info['service']}")
        print("\n[r] Salvar | [s] Voltar")
        choice = input("Escolha: ").strip()
        if choice.lower() == "s": return False
        if choice.lower() == "r": save_report_menu(report)
        elif choice.isdecimal() and int(choice) < len(report["open_ports"]):
            if off_angel_menu(report, report["open_ports"][int(choice)]): return True
        else:
            print(f"{Fore.RED}[!] Índice inválido."); pause()

def start_scanner() -> bool:
    header("[ NOVA ANÁLISE ]")
    try:
        target = validate_target(input("Alvo (IP/Host): "))
    except ValueError as exc:
        print(f"{Fore.RED}[!] {exc}"); pause(); return False
    selected = choose_scan_mode()
    if not selected: return False
    mode, ports = selected
    report = new_report(target, mode, ports)
    try:
        report.update(scan_ports(target, ports))
    except Exception as exc:
        report.update(status="erro", message=str(exc), finished_at=now_iso())
    return ports_menu(report)


def start_web_scanner() -> bool:
    header("[ WEBSITE SECURITY SCANNER ]")
    try:
        target_url = validate_web_url(input("[+] Digite a URL do site (http/https): ").strip())
        from urllib.parse import urlsplit

        target = validate_target(urlsplit(target_url).hostname or "")
    except ValueError as exc:
        print(f"{Fore.RED}[!] {exc}")
        pause()
        return False
    print("\n[!] Confirme que possui autorização para testar este site.")
    if input("Possui autorização? [s/N]: ").strip().lower() != "s":
        print("Análise cancelada; nenhuma requisição foi enviada.")
        return False
    report = new_report(target, "website", None)
    report["web_target"] = target_url
    print("\n[1] Iniciar análise   [2] Configurações do Nuclei   [3] Voltar")
    choice = input("Escolha: ").strip()
    if choice == "2":
        nuclei_settings_menu()
        return False
    if choice != "1":
        return False
    print("[+] Validando URL...")
    try:
        result = run_web_scan(
            target_url,
            nuclei_settings=load_config()["nuclei"],
            progress_callback=lambda message: print(f"[+] {message}"),
        )
        report.update(
            status=result.get("status", "erro"),
            execution_status=result.get("execution_status", "failed"),
            address=result.get("address", "desconhecido"),
            tools=result.get("tools", []),
            nuclei_findings=result.get("nuclei_findings", []),
            finished_at=result.get("finished_at", now_iso()),
            message=result.get("message", ""),
            consolidated_findings=result.get("consolidated_findings", []),
            confirmed_findings=result.get("confirmed_findings", []),
            unconfirmed_findings=result.get("unconfirmed_findings", []),
            operational_errors=result.get("operational_errors", []),
            recommendations=result.get("recommendations", []),
        )
        http = result.get("http", {})
        report["web_metadata"] = {
            "hostname": target,
            "protocol": result.get("target", {}).get("protocol"),
            "port": result.get("target", {}).get("port"),
            "http_status": http.get("http_status"),
            "final_url": http.get("final_url"),
            "redirects": http.get("redirects", []),
            "headers": http.get("headers", {}),
            "technologies": http.get("technologies", []),
        }
        report["vulnerabilities"] = [
            finding
            for tool in report["tools"]
            for finding in (tool.get("alerts", []) + tool.get("findings", []))
        ] + report["nuclei_findings"]
        counts = result.get("nuclei_severity_counts", {})
        if result.get("status") == "erro" and not result.get("tools"):
            print(f"{Fore.RED}[!] {result.get('message', 'Scan web não iniciado.')}")
        elif counts:
            print("\nAchados Nuclei por severidade:")
            for severity in ("Critical", "High", "Medium", "Low", "Informational", "Unknown"):
                print(f"{severity}: {counts.get(severity, 0)}")
        else:
            nuclei_summary = next(
                (item for item in result.get("tools", []) if item.get("tool") == "Nuclei"),
                {"status": "indisponível", "message": "Nuclei não executado."},
            )
            print(f"Nuclei: {nuclei_summary.get('status')}. {nuclei_summary.get('message', '')}")
    except Exception as exc:
        report.update(status="erro", message=clean_text(str(exc)), finished_at=now_iso())
        print(f"{Fore.RED}[!] Erro no scan web: {clean_text(str(exc))}")
    print("[+] Consolidando resultados...")
    print("[+] Gerando relatórios TXT e JSON...")
    for fmt in ("txt", "json"):
        try:
            path = save_report(report, fmt)
            print(f"{Fore.GREEN}[+] Salvo: {path}")
        except Exception as exc:
            print(f"{Fore.RED}[!] Erro ao salvar: {clean_text(str(exc))}")
    return False



def start_controlled_load_test() -> bool:
    header("[ TESTE DE CARGA HTTP CONTROLADO ]")
    try:
        target_url = validate_web_url(input("URL autorizada (http/https): ").strip())
        from urllib.parse import urlsplit

        target = urlsplit(target_url).hostname or ""
        target = validate_target(target)
    except ValueError as exc:
        print(f"{Fore.RED}[!] {exc}")
        pause()
        return False
    print("O teste envia no maximo 1 requisicao HEAD por segundo durante ate 30 segundos.")
    if input("Voce e proprietario ou tem autorizacao explicita? [s/N]: ").strip().lower() != "s":
        print("Teste cancelado; nenhuma requisicao foi enviada.")
        return False
    value = input("Duracao em segundos [10, maximo 30]: ").strip() or "10"
    try:
        duration = int(value)
        result = run_controlled_http_test(target_url, authorized=True, duration=duration)
    except (ValueError, OSError) as exc:
        print(f"{Fore.RED}[!] Parametro ou teste invalido: {clean_text(str(exc))}")
        pause()
        return False
    report = new_report(target, "teste-http-controlado", None)
    report.update(status=result["status"], web_target=target_url, tools=[result], message=result["message"])
    print(f"Requisicoes: {result['requests_sent']} | Latencia media: {result['average_latency_ms']} ms")
    print(f"Codigos HTTP: {result['http_status_counts']} | Erros: {result['errors']}")
    for fmt in ("txt", "json"):
        try:
            print(f"[+] Salvo: {save_report(report, fmt)}")
        except Exception as exc:
            print(f"{Fore.RED}[!] Erro ao salvar: {clean_text(str(exc))}")
    return False

def nuclei_settings_menu() -> None:
    while True:
        settings = load_config()["nuclei"]
        header("[ CONFIGURAÇÕES DO NUCLEI ]")
        print(f"Ativado: {'sim' if settings['enabled'] else 'não'}")
        print(f"Executável: {settings['executable_path'] or 'automático'}")
        print(f"Templates: {settings['templates_directory'] or 'automático'}")
        print(
            f"Timeout global: {settings['timeout']} s | Requisições/s: {settings['rate_limit']} | "
            f"Concorrência: {settings['concurrency']}"
        )
        print("[1] Ativar/desativar  [2] Executável  [3] Diretório de templates")
        print("[4] Timeout  [5] Limite de requisições  [6] Concorrência")
        print("[7] Atualizar templates manualmente  [8] Voltar")
        choice = input("Escolha: ").strip()
        if choice == "8":
            return
        try:
            if choice == "1":
                settings["enabled"] = not settings["enabled"]
            elif choice in {"2", "3"}:
                key = "executable_path" if choice == "2" else "templates_directory"
                value = input("Caminho (digite 'auto' para localizar automaticamente): ").strip()
                if value:
                    settings[key] = "" if value.lower() == "auto" else value
            elif choice in {"4", "5", "6"}:
                key = {"4": "timeout", "5": "rate_limit", "6": "concurrency"}[choice]
                value = input("Novo valor: ").strip()
                if value:
                    settings[key] = int(value)
            elif choice == "7":
                answer = input("Atualizar agora os templates oficiais? [s/N]: ").strip().lower()
                if answer == "s":
                    result = update_nuclei_templates(
                        confirm=True,
                        executable=settings["executable_path"] or None,
                        templates_dir=settings["templates_directory"] or None,
                        timeout=settings["timeout"],
                    )
                    print(f"[{result['status']}] {result['message']}")
                else:
                    print("Atualização cancelada; nenhuma alteração foi feita.")
                pause()
                continue
            else:
                print(f"{Fore.RED}[!] Opção inválida.")
                pause()
                continue
            save_config({"nuclei": settings})
            print("Configurações salvas.")
            pause()
        except (ValueError, OSError) as exc:
            print(f"{Fore.RED}[!] Configuração inválida: {clean_text(str(exc))}")
            pause()

# --- MAIN ---

def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    init(autoreset=True)

    while True:
        try:
            header("[ MENU PRINCIPAL ]")
            print(f"{Fore.CYAN}[1] Iniciar scan de portas")
            print(f"{Fore.CYAN}[2] Verificar dependências")
            print(f"{Fore.CYAN}[3] Ver relatórios")
            print(f"{Fore.CYAN}[4] Ajuda")
            print(f"{Fore.CYAN}[5] Sair")
            print(f"{Fore.CYAN}[6] Scan de segurança web (URL)")
            print(f"{Fore.CYAN}[7] Configurações do Nuclei")
            print(f"{Fore.CYAN}[8] Website Security Scanner")
            print(f"{Fore.CYAN}[9] Teste de carga HTTP controlado")

            choice = input("Escolha uma opção: ").strip().lower()

            if choice == "1":
                start_scanner()
            elif choice == "2":
                show_dependencies()
            elif choice == "3":
                view_reports()
            elif choice == "4":
                show_help()
            elif choice == "5":
                print(f"\n{Fore.YELLOW}[!] OFF ANGELL encerrado.")
                return
            elif choice == "6":
                start_web_scanner()
            elif choice == "7":
                nuclei_settings_menu()
            elif choice == "8":
                start_web_scanner()
            elif choice == "9":
                start_controlled_load_test()
            else:
                print(f"{Fore.RED}[!] Opção inválida.")
                pause()

        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}[!] OFF ANGELL encerrado.")
            return
        except Exception as exc:
            print(f"{Fore.RED}[!] Erro crítico: {exc}")
            try:
                pause()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Fore.YELLOW}[!] OFF ANGELL encerrado.")
                return

if __name__ == "__main__":
    main()
