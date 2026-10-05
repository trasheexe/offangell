import os
import socket
import sys
import subprocess
import nmap
from colorama import Fore, init

# Inicializa as cores no terminal
init(autoreset=True)

# Caminhos onde o programa tentará encontrar o Nmap
NMAP_PATHS = (
    "nmap",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
)

NIKTO_PATHS = (
    "nikto",
    "nikto.pl",
    r"C:\nikto\program\nikto.pl",
    r"C:\Program Files\Nikto\program\nikto.pl",
    "/usr/bin/nikto",
    "/usr/local/bin/nikto",
    "/usr/share/nikto/nikto.pl",
)

ZAP_PATHS = (
    "zap",
    "zap.sh",
    "zaproxy",
    r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat",
    r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
    "/usr/bin/zaproxy",
    "/usr/bin/zap.sh",
    "/usr/share/zaproxy/zap.sh",
)

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def pause():
    input("\nPressione Enter para continuar...")

def print_banner():
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

def create_scanner():
    try:
        return nmap.PortScanner(nmap_search_path=NMAP_PATHS)
    except nmap.PortScannerError:
        print(f"{Fore.RED}[!] Nmap não foi encontrado.")
        sys.exit(1)

def banner_grabbing(target, port):
    print(f"\n{Fore.CYAN}[+] Coletando banner da porta {port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((target, port))
        s.sendall(b"\r\n")
        banner = s.recv(1024)
        if banner:
            print(f"{Fore.GREEN}[+] Resultado:\n{banner.decode(errors='ignore').strip()}")
        else:
            print(f"{Fore.YELLOW}[-] Nenhum banner retornado.")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {e}")
    finally:
        s.close()

def run_nikto(target, port):
    print(f"\n{Fore.MAGENTA}[*] Iniciando NIKTO Scan na porta {port}...")
    print(f"{Fore.YELLOW}[!] O Nikto pode demorar alguns minutos para analisar o servidor web.")
    try:
        # Comando: nikto -h <target> -p <port>
        cmd = ["nikto", "-h", target, "-p", str(port)]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        for line in process.stdout:
            print(line, end="")
            
        process.wait()
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Erro: Nikto não instalado ou não encontrado no PATH do sistema.")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro inesperado no Nikto: {e}")

def run_zap(target, port):
    print(f"\n{Fore.MAGENTA}[*] Iniciando OWASP ZAP Baseline Scan na porta {port}...")
    print(f"{Fore.YELLOW}[!] Requer que o ZAP esteja instalado e configurado no PATH.")
    try:
        # Exemplo de chamada para o script de baseline do ZAP (via docker ou instalação local)
        # Ajuste o comando conforme sua instalação (ex: zap-baseline.py)
        url = f"http://{target}:{port}"
        cmd = ["zap-baseline.py", "-t", url]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        for line in process.stdout:
            print(line, end="")
            
        process.wait()
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Erro: zap-baseline.py não encontrado. Instale o OWASP ZAP.")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro inesperado no ZAP: {e}")

def vulnerability_scan(target, port):
    print(f"\n{Fore.CYAN}[+] Executando análise NSE na porta {port}...")
    try:
        scanner = create_scanner()
        vuln_scan = scanner.scan(hosts=target, ports=str(port), arguments="-sV --script vuln")
        hosts = list(vuln_scan.get("scan", {}).keys())
        if not hosts:
            print(f"{Fore.YELLOW}[-] Nenhum resultado.")
            return
        scan_host = hosts[0]
        scripts = vuln_scan.get("scan", {}).get(scan_host, {}).get("tcp", {}).get(port, {}).get("script", {})
        if scripts:
            for script_name, result in scripts.items():
                print(f"\n{Fore.YELLOW}[{script_name}]\n{result}")
        else:
            print(f"{Fore.YELLOW}[-] Nenhuma vulnerabilidade NSE encontrada.")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {e}")

def off_angel_menu(target, port):
    while True:
        clear_screen()
        print_banner()
        print(f"{Fore.CYAN}--- [ OFF ANGELL ] ---")
        print(f"Alvo: {target} | Porta Aberta: {port}")
        print("-" * 45)
        print(f"{Fore.CYAN}[1] Analisar Serviço (Banner Grabbing)")
        print(f"{Fore.CYAN}[2] Verificar Vulnerabilidades (Nmap NSE)")
        print(f"{Fore.CYAN}[3] Executar NIKTO (Web Scan)")
        print(f"{Fore.CYAN}[4] Executar OWASP ZAP (Baseline)")
        print(f"{Fore.CYAN}[5] Voltar ao Scanner")
        print(f"{Fore.CYAN}[6] Sair")
        print("-" * 45)

        choice = input("Escolha uma opção: ").strip()

        if choice == "1":
            banner_grabbing(target, port)
            pause()
        elif choice == "2":
            vulnerability_scan(target, port)
            pause()
        elif choice == "3":
            run_nikto(target, port)
            pause()
        elif choice == "4":
            run_zap(target, port)
            pause()
        elif choice == "5":
            break
        elif choice == "6":
            sys.exit(0)
        else:
            print(f"{Fore.RED}[!] Opção inválida!")
            pause()

def start_scanner():
    clear_screen()
    print_banner()
    target = input("Digite o IP ou Hostname do alvo: ").strip()
    if not target: return

    nm = create_scanner()
    print(f"\n{Fore.CYAN}[*] Escaneando todas as portas de {target}... Aguarde.")
    try:
        nm.scan(hosts=target, ports="1-65535", arguments="-sV")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {e}"); return

    hosts = nm.all_hosts()
    if not hosts:
        print(f"{Fore.RED}[-] Alvo offline."); return

    scan_host = hosts[0]
    open_ports = []
    for proto in nm[scan_host].all_protocols():
        for port in nm[scan_host][proto].keys():
            if nm[scan_host][proto][port]["state"] == "open":
                open_ports.append({"port": port, "protocol": proto, "service": nm[scan_host][proto][port].get("name", "desconhecido")})

    if not open_ports:
        print(f"{Fore.YELLOW}[-] Nenhuma porta aberta."); return

    open_ports.sort(key=lambda item: item["port"])
    
    while True:
        clear_screen()
        print_banner()
        print(f"{Fore.CYAN}--- [ PORTAS ABERTAS ] ---\n")
        for i, info in enumerate(open_ports):
            print(f"{Fore.CYAN}[{i}] Porta {info['port']}/{info['protocol']} ({info['service']})")
        
        print("\n" + "-" * 55)
        print(f"{Fore.CYAN}Digite o número da porta para o menu OFF ANGELL ou 's' para sair.")
        user_input = input("\nOpção: ").strip()
        if user_input.lower() == "s": break
        try:
            idx = int(user_input)
            if 0 <= idx < len(open_ports):
                off_angel_menu(target, open_ports[idx]["port"])
        except ValueError:
            print(f"{Fore.RED}[!] Entrada inválida!"); pause()

if __name__ == "__main__":
    try:
        start_scanner()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Encerrado.")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erro: {e}")
