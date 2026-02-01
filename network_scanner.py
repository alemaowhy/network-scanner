#!/usr/bin/env python3
"""
Advanced Network Security Scanner
Autor: Gabriel (@alemaowhy)
Descrição: Scanner de rede para pentest com detecção de serviços, banner grabbing e checks básicos de segurança.
"""

import socket
import ipaddress
import concurrent.futures
from argparse import ArgumentParser

def scan_port(target_ip, port):
    """Tenta conectar em uma porta específica e identifica o serviço."""
    try:
        # Cria o socket e tenta conexão com timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))

        if result == 0:  # Conexão bem-sucedida (porta aberta)
            # Tenta obter o banner do serviço
            banner = get_banner(sock, target_ip, port)
            service = identify_service(port, banner)

            # Verificação de segurança básica
            security_note = check_security(port, banner)

            print(f"[+] Porta {port}/TCP aberta - Serviço: {service}")
            if banner:
                print(f"    Banner: {banner}")
            if security_note:
                print(f"    [!] {security_note}")

            sock.close()
            return port, service, banner, security_note
        sock.close()
    except Exception as e:
        pass
    return None

def get_banner(sock, ip, port):
    """Tenta receber um banner de serviço após conexão."""
    try:
        # Aumenta um pouco o timeout para receber dados
        sock.settimeout(2)

        # Envia uma solicitação genérica para serviços comuns
        if port == 22:  # SSH
            sock.send(b'SSH-2.0-Client\r\n')
        elif port == 80 or port == 443:  # HTTP/HTTPS
            sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
        elif port == 21:  # FTP
            sock.send(b'\r\n')

        # Tenta receber até 512 bytes
        banner = sock.recv(512).decode(errors='ignore').strip()
        return banner if banner else "Nenhum banner recebido"
    except:
        return "Banner não disponível"

def identify_service(port, banner=""):
    """Identifica o serviço com base na porta e no banner."""
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Proxy",
    }
    service = common_ports.get(port, "Serviço Desconhecido")

    # Refina a identificação com base no banner
    if "Apache" in banner or "nginx" in banner:
        service = "Web Server"
    elif "OpenSSH" in banner:
        service = "OpenSSH"
    elif "Microsoft" in banner and "RDP" in banner:
        service = "Windows RDP"

    return service

def check_security(port, banner=""):
    """Verifica problemas de segurança comuns."""
    # SSH com versão antiga/Insegura
    if port == 22 and ("SSH-1.99" in banner or "SSH-1.5" in banner):
        return "SSH versão 1.x detectada (INSECURA)"
    # HTTP sem redirecionamento para HTTPS
    if port == 80 and "HTTPS" not in banner:
        return "Serviço HTTP sem redirecionamento óbvio para HTTPS"
    # Serviços com credenciais padrão
    if port in [21, 23, 3306]:
        return "Serviço que frequentemente usa credenciais padrão/fraco"
    return None

def main():
    parser = ArgumentParser(description="Scanner de Rede Avançado para Pentest")
    parser.add_argument("-t", "--target", required=True, help="IP alvo ou rede (ex: 192.168.1.1 ou 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Intervalo de portas (ex: 1-1000 ou 22,80,443)")
    args = parser.parse_args()

    print(f"[*] Iniciando varredura no alvo: {args.target}")
    print("[*] Usando técnicas de detecção ativa de serviços\n")

    open_ports_info = []

    # Processa o alvo (pode ser um IP único ou rede)
    try:
        network = ipaddress.ip_network(args.target, strict=False)
        target_ips = [str(ip) for ip in network.hosts()]
        print(f"[*] Varrendo rede: {args.target} ({len(target_ips)} hosts)")
    except ValueError:
        # Se não for uma rede, trata como IP único
        target_ips = [args.target]

    # Processa o intervalo de portas
    if '-' in args.ports:
        start_port, end_port = map(int, args.ports.split('-'))
        ports_to_scan = range(start_port, end_port + 1)
    else:
        ports_to_scan = [int(p) for p in args.ports.split(',')]

    # Scanner com multi-threading para velocidade
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for target_ip in target_ips:
            print(f"\n[*] Scan no host: {target_ip}")
            futures = [executor.submit(scan_port, target_ip, port) for port in ports_to_scan]

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    port, service, banner, security_note = result
                    open_ports_info.append({
                        'host': target_ip,
                        'port': port,
                        'service': service,
                        'banner': banner,
                        'note': security_note
                    })

    # Resumo final
    if open_ports_info:
        print(f"\n{'='*50}")
        print("RESUMO DA VARREURA:")
        print(f"Total de portas abertas encontradas: {len(open_ports_info)}")
        for info in open_ports_info:
            print(f"  {info['host']}:{info['port']} - {info['service']}")
            if info['note']:
                print(f"      AVISO: {info['note']}")
    else:
        print("\n[!] Nenhuma porta aberta encontrada no intervalo especificado.")

if __name__ == "__main__":
    main()