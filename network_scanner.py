#!/usr/bin/env python3
"""
Network Security Scanner
Ferramenta para varredura de rede e detecção de vulnerabilidades
"""

import socket
import threading
import argparse
from datetime import datetime

def scan_port(target, port):
    """Escaneia uma porta específica no alvo"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = "unknown"
            
            print(f"[+] Port {port} open - {service.upper()}")
            
            # Detecção básica de vulnerabilidades
            if port == 22:
                print(f"    [!] SSH - Verificar autenticação forte")
            elif port == 80 or port == 443:
                print(f"    [!] HTTP/S - Verificar configurações de segurança")
            elif port == 3389:
                print(f"    [!] RDP - Possível acesso remoto desprotegido")
                
        sock.close()
    except Exception as e:
        pass

def main():
    """Função principal"""
    print("🔍 Network Security Scanner")
    print("=" * 40)
    
    parser = argparse.ArgumentParser(description='Network Security Scanner')
    parser.add_argument('--target', required=True, help='IP ou range a ser escaneado')
    parser.add_argument('--ports', default='1-1000', help='Range de portas (ex: 1-1000)')
    
    args = parser.parse_args()
    
    target = args.target
    port_range = args.ports
    
    # Parse do range de portas
    if '-' in port_range:
        start_port, end_port = map(int, port_range.split('-'))
    else:
        start_port = end_port = int(port_range)
    
    print(f"[+] Iniciando scan em: {target}")
    print(f"[+] Portas: {start_port}-{end_port}")
    print(f"[+] Hora de início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 40)
    
    # Escaneamento multi-thread
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()
    
    # Aguarda todas as threads terminarem
    for thread in threads:
        thread.join()
    
    print("-" * 40)
    print("[+] Scan finalizado!")

if __name__ == "__main__":
    main()
