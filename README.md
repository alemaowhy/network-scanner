# 🔍 Advanced Network Security Scanner

Uma ferramenta Python de propósito específico para profissionais de *cybersecurity*, focada na fase inicial de reconhecimento em testes de penetração ou avaliações de rede interna.

## 🎯 Objetivo & Contexto Profissional
Este projeto vai além de um simples *port scanner*. Ele automatiza a coleta de inteligência ativa (**Active Reconnaissance**), identificando serviços expostos, coletando *banners* para *fingerprinting* e sinalizando configurações potencialmente inseguras. É uma ferramenta para ser usada em ambientes controlados e autorizados.

## 🚀 Funcionalidades (Feature Set)
*   **Varredura Rápida de Portas TCP**: Utiliza *multi-threading* para escanear intervalos de portas de forma eficiente.
*   **Detecção Inteligente de Serviços**: Mapeia portas comuns (22/SSH, 80/HTTP, etc.) e usa heurística para identificar serviços em portas não padrão.
*   **Banner Grabbing Automatizado**: Conecta-se a serviços abertos para extrair banners, cruciais para identificar versões de software (ex: `OpenSSH 8.2p1`).
*   **Verificação de Segurança Básica**: Sinaliza potenciais problemas:
    *   Serviço SSH usando versão protocolo 1.x (insegura).
    *   Serviço HTTP sem redirecionamento óbvio para HTTPS.
    *   Serviços conhecidos por usar credenciais padrão (FTP, Telnet, MySQL).
*   **Suporte a Rede CIDR**: Escaneia uma faixa de IPs de uma vez (ex: `192.168.1.0/24`).

## 🛠️ Tecnologias & Conceitos Aplicados
*   **Linguagem**: Python 3
*   **Conceitos de Redes**: Sockets TCP, conexões simultâneas, análise de protocolos.
*   **Conceitos de Segurança**: Reconhecimento ativo, *banner grabbing*, *fingerprinting*, identificação de *misconfigurations*.
*   **Ferramentas Relacionadas**: Complementa ferramentas como `nmap` (focado em verificação rápida e automatizada).

## 📦 Instalação & Uso
1.  **Clone o repositório**:
    ```bash
    git clone https://github.com/alemaowhy/network-scanner.git
    cd network-scanner
    ```

2.  **Instale as dependências** (opcional, para saída colorida):
    ```bash
    pip install -r requirements.txt
    ```

3.  **Execute o Scanner**:

    *   **Host único**:
        ```bash
        python network_scanner.py --target 192.168.1.105
        ```
    *   **Intervalo de portas específico**:
        ```bash
        python network_scanner.py --target 192.168.1.1 --ports 20-100
        ```
    *   **Varredura de rede completa**:
        ```bash
        python network_scanner.py --target 192.168.1.0/24 --ports 22,80,443,3306
        ```

## 📸 Demonstração Prática
Abaixo está uma saída real do scanner em ação durante um teste interno:

```bash
[*] Iniciando varredura no alvo: 192.168.1.1
[*] Usando técnicas de detecção ativa de serviços

[*] Scan no host: 192.168.1.1
[+] Porta 22/TCP aberta - Serviço: OpenSSH
    Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
[+] Porta 80/TCP aberta - Serviço: Web Server
    Banner: HTTP/1.1 200 OK Server: nginx/1.18.0
    [!] Serviço HTTP sem redirecionamento óbvio para HTTPS
[+] Porta 443/TCP aberta - Serviço: Web Server
    Banner: HTTP/1.1 200 OK Server: nginx/1.18.0

==================================================
RESUMO DA VARREURA:
Total de portas abertas encontradas: 3
  192.168.1.1:22 - OpenSSH
  192.168.1.1:80 - Web Server
      AVISO: Serviço HTTP sem redirecionamento óbvio para HTTPS
  192.168.1.1 - Web Server