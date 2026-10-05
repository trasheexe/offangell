import sys
from types import SimpleNamespace

if sys.version_info < (3, 10):
    raise SystemExit("OFF ANGELL requer Python 3.10 ou superior.")

try:
    from colorama import Fore, init
except ImportError:
    Fore = SimpleNamespace(CYAN="", RED="", GREEN="", YELLOW="", MAGENTA="", RESET="")

    def init(**kwargs):
        pass


from core.reports import (
    clean_text,
    list_reports,
    new_report,
    now_iso,
    read_report,
    save_report,
)
from core.scanner import ScanError, banner_grabbing, scan_ports, vulnerability_scan
from core.tools import dependency_status, run_nikto, run_zap
from core.validation import is_web_service, validate_ports, validate_target


def clear_screen() -> None:
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def pause() -> None:
    input("\nPressione Enter para continuar...")


def print_banner() -> None:
    print(
        f"""
{Fore.CYAN} ██████╗ ███████╗███████╗     █████╗ ███╗   ██╗ ██████╗ ███████╗██╗     ██╗
{Fore.CYAN}██╔═══██╗██╔════╝██╔════╝    ██╔══██╗████╗  ██║██╔════╝ ██╔════╝██║     ██║
{Fore.CYAN}██║   ██║█████╗  █████╗      ███████║██╔██╗ ██║██║  ███╗█████╗  ██║     ██║
{Fore.CYAN}██║   ██║██╔══╝  ██╔══╝      ██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██║     ██║
{Fore.CYAN}╚██████╔╝██║     ██║         ██║  ██║██║ ╚████║╚██████╔╝███████╗███████╗███████╗
{Fore.CYAN} ╚═════╝ ╚═╝     ╚═╝         ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝
{Fore.RESET}
"""
    )


def header(title: str) -> None:
    clear_screen()
    print_banner()
    print(f"{Fore.CYAN}{'=' * 60}\n{title}\n{'=' * 60}")


def show_dependencies() -> None:
    header("[ DEPENDÊNCIAS ]")
    for name, available, detail in dependency_status():
        color = Fore.GREEN if available else Fore.YELLOW
        print(f"{color}[{'OK' if available else '--'}] {name}: {detail}")
    print("\nNikto e ZAP são opcionais. Sem colorama, a interface funciona sem cores.")
    pause()


def show_help() -> None:
    header("[ AJUDA ]")
    print(
        "OFF ANGELL foi desenvolvido para aprendizado, laboratórios, CTFs\n"
        "e testes de segurança autorizados. Utilize apenas em sistemas\n"
        "próprios ou nos quais você tenha autorização explícita.\n\n"
        "Informe um único hostname/IP, sem URL, porta ou rede CIDR.\n"
        "Escolha o modo de scan e depois o índice da porta na lista.\n"
        "NSE, Nikto e ZAP só são iniciados pela escolha no menu da porta.\n"
        "NSE apresenta indícios; seus resultados exigem revisão.\n"
        "Use 'r' na lista de portas para salvar TXT ou JSON em reports/.\n"
        "Ctrl+C cancela uma análise; no menu principal, encerra o programa."
    )
    pause()


def choose_scan_mode() -> tuple[str, str | None] | None:
    while True:
        header("[ MODO DE SCAN ]")
        print(
            "[1] Scan rápido — 100 portas TCP mais comuns\n"
            "[2] Scan completo — TCP 1-65535\n"
            "[3] Intervalo personalizado\n[4] Voltar"
        )
        choice = input("Escolha uma opção: ").strip()
        if choice == "1":
            return "rápido", None
        if choice == "2":
            return "completo", "1-65535"
        if choice == "3":
            try:
                ports = validate_ports(input("Portas (ex.: 1-1000 ou 22,80,443): "))
                return "personalizado", ports
            except ValueError as exc:
                print(f"{Fore.RED}[!] {exc}")
                pause()
        elif choice == "4":
            return None
        else:
            print(f"{Fore.RED}[!] Opção inválida.")
            pause()


def save_report_menu(report: dict) -> None:
    choice = input("Salvar como [1] TXT, [2] JSON ou [3] Voltar: ").strip()
    if choice == "3":
        return
    if choice not in {"1", "2"}:
        print(f"{Fore.RED}[!] Formato inválido.")
    else:
        try:
            path = save_report(report, "txt" if choice == "1" else "json")
            print(f"{Fore.GREEN}[+] Relatório salvo: {path}")
        except (OSError, ValueError) as exc:
            print(f"{Fore.RED}[!] Não foi possível salvar o relatório: {exc}")
    pause()


def view_reports() -> None:
    while True:
        header("[ RELATÓRIOS LOCAIS ]")
        try:
            paths = list_reports()
            if not paths:
                print("Nenhum relatório salvo em reports/.")
                pause()
                return
            for index, path in enumerate(paths):
                print(f"[{index}] {path.name}")
            choice = input("Digite o índice do relatório ou 'v' para voltar: ").strip()
            if choice.lower() == "v":
                return
            if not choice.isascii() or not choice.isdecimal() or int(choice) >= len(paths):
                print(f"{Fore.RED}[!] Índice inválido.")
            else:
                print(read_report(paths[int(choice)]))
        except (OSError, ValueError) as exc:
            print(f"{Fore.RED}[!] Não foi possível ler os relatórios: {exc}")
        pause()


def show_service(info: dict) -> None:
    for key, label in (
        ("port", "Porta"),
        ("protocol", "Protocolo"),
        ("service", "Serviço"),
        ("product", "Produto"),
        ("version", "Versão"),
        ("extrainfo", "Detalhes"),
        ("tunnel", "Túnel"),
    ):
        print(f"{label}: {clean_text(str(info.get(key) or 'desconhecido'))}")


def analyze_port(choice: str, report: dict, info: dict) -> None:
    target, port = report["target"], info["port"]
    key = {"2": "banners", "3": "nse", "4": "tools", "5": "tools"}[choice]
    if choice in {"4", "5"} and not is_web_service(port, info):
        print(f"{Fore.YELLOW}[!] O serviço selecionado não foi identificado como HTTP/HTTPS.")
        return
    print(f"{Fore.CYAN}[*] Analisando {target}:{port}. Ctrl+C cancela a análise.")
    try:
        if choice == "2":
            result = banner_grabbing(target, port, info)
            print(result.get("banner") or result["message"])
        elif choice == "3":
            print(
                f"\n{'=' * 40}\nANÁLISE NSE\n{'=' * 40}\n"
                f"Alvo: {target}\nPorta: {port}\nServiço: {clean_text(info['service'])}\n"
            )
            result = vulnerability_scan(report.get("address", target), port)
            print("Scripts com resultados retornados:")
            for name, output in result["scripts"].items():
                print(f"\n[{clean_text(name)}]\n{output}")
            if not result["scripts"]:
                print("Nenhum resultado relevante retornado pelos scripts NSE.")
            if result.get("message"):
                print(result["message"])
            print("\nResultados são indícios e não confirmam vulnerabilidades.")
        else:
            runner = run_nikto if choice == "4" else run_zap
            result = runner(target, port, info)
            print(f"\n{clean_text(result['message'])}")
    except (ScanError, ValueError, OSError) as exc:
        result = {"port": port, "at": now_iso(), "status": "erro", "message": clean_text(str(exc))}
        print(f"{Fore.RED}[!] {result['message']}")
    except KeyboardInterrupt:
        result = {
            "port": port,
            "at": now_iso(),
            "status": "cancelado",
            "message": "Análise cancelada com Ctrl+C.",
        }
        print(f"\n{Fore.YELLOW}[!] {result['message']}")
    report[key].append(result)


def off_angel_menu(report: dict, info: dict) -> bool:
    while True:
        header("[ OFF ANGELL ]")
        print(
            f"Alvo: {report['target']}\nPorta: {info['port']}\nServiço: {clean_text(info['service'])}\n"
        )
        print(
            "[1] Informações do serviço\n[2] Banner\n[3] Análise NSE\n"
            "[4] Nikto\n[5] ZAP Baseline\n[6] Salvar relatório\n[7] Voltar\n[8] Sair"
        )
        choice = input("Escolha uma opção: ").strip()
        if choice == "7":
            return False
        if choice == "8":
            return True
        if choice == "6":
            save_report_menu(report)
            continue
        if choice == "1":
            show_service(info)
        elif choice in {"2", "3", "4", "5"}:
            analyze_port(choice, report, info)
        else:
            print(f"{Fore.RED}[!] Opção inválida.")
        pause()


def ports_menu(report: dict) -> bool:
    while True:
        header("[ PORTAS ABERTAS ]")
        print(f"Alvo: {report['target']} | Endereço: {report.get('address', 'desconhecido')}\n")
        if report.get("message"):
            print(clean_text(report["message"]))
        if not report["open_ports"]:
            print("Nenhuma porta aberta registrada nesta análise.")
        for index, info in enumerate(report["open_ports"]):
            label = f"{info['port']}/{info['protocol']}"
            print(
                f"{Fore.CYAN}[{index}] {label:<10} OPEN  {clean_text(info['service']):<14} "
                f"{clean_text(info['product'])} {clean_text(info['version'])}"
            )
        print("\n[r] Salvar relatório antes de sair | [s] Voltar ao menu principal")
        choice = input(
            "Digite o índice da porta desejada, 'r' para salvar ou 's' para sair: "
        ).strip()
        if choice.lower() == "s":
            return False
        if choice.lower() == "r":
            save_report_menu(report)
        elif choice.isascii() and choice.isdecimal() and int(choice) < len(report["open_ports"]):
            if off_angel_menu(report, report["open_ports"][int(choice)]):
                return True
        else:
            print(f"{Fore.RED}[!] Índice inválido. Escolha um dos índices entre colchetes.")
            pause()


def start_scanner() -> bool:
    header("[ NOVA ANÁLISE ]")
    try:
        target = validate_target(input("Digite o IP ou hostname do alvo: "))
    except ValueError as exc:
        print(f"{Fore.RED}[!] {exc}")
        pause()
        return False
    selected = choose_scan_mode()
    if selected is None:
        return False
    mode, ports = selected
    report = new_report(target, mode, ports)
    print(f"{Fore.CYAN}[*] Scan {mode} de {target}. Aguarde; Ctrl+C cancela.")
    try:
        report.update(scan_ports(target, ports))
    except (ScanError, ValueError, OSError) as exc:
        report.update(status="erro", message=clean_text(str(exc)), finished_at=now_iso())
    except KeyboardInterrupt:
        report.update(
            status="cancelado", message="Scan cancelado com Ctrl+C.", finished_at=now_iso()
        )
    return ports_menu(report)


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    init(autoreset=True)
    while True:
        try:
            header("[ MENU PRINCIPAL ]")
            print(
                "Scanner defensivo para ambientes próprios ou autorizados.\n\n"
                "[1] Iniciar scan\n[2] Verificar dependências\n"
                "[3] Visualizar relatórios\n[4] Ajuda\n[5] Sair"
            )
            choice = input("Escolha uma opção: ").strip()
            if choice == "5":
                print("OFF ANGELL encerrado.")
                return
            if choice == "1":
                if start_scanner():
                    return
            elif choice == "2":
                show_dependencies()
            elif choice == "3":
                view_reports()
            elif choice == "4":
                show_help()
            else:
                print(f"{Fore.RED}[!] Opção inválida.")
                pause()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}[!] OFF ANGELL encerrado.")
            return
        except Exception as exc:
            print(f"{Fore.RED}[!] Não foi possível concluir a operação: {clean_text(str(exc))}")
            try:
                pause()
            except (KeyboardInterrupt, EOFError):
                print("\nOFF ANGELL encerrado.")
                return


if __name__ == "__main__":
    main()
