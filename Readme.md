# 🧪 Python Security Toolkit - Documentação Oficial

> **Laboratório Educacional para Estudo de Segurança Cibernética em Python**

<div align="center">

[![Educational Purpose](https://img.shields.io/badge/purpose-educational-brightgreen.svg)](https://github.com/Security-Labor/Automation-Toolkit)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Code style](https://img.shields.io/badge/code%20style-PEP%208-ff69b4.svg)](https://www.python.org/dev/peps/pep-0008/)
[![Documentation](https://img.shields.io/badge/docs-passing-success.svg)](https://security-labor.github.io/Automation-Toolkit/)

</div>

---

## 📑 Índice

- [📖 Sobre o Projeto](#-sobre-o-projeto)
- [🎓 Contexto Acadêmico](#-contexto-acadêmico)
- [⚠️ Aviso Legal](#️-aviso-legal)
- [⚙️ Funcionalidades Principais](#️-funcionalidades-principidades)
- [📦 Estrutura do Projeto](#-estrutura-do-projeto)
- [🔧 Pré-requisitos](#-pré-requisitos)
- [📥 Instalação](#-instalação)
- [🛠️ Módulos e Ferramentas](#️-módulos-e-ferramentas)
  - [1. TCP Scanner Simples](#1-tcp-scanner-simples)
  - [2. Multi-Thread Scanner](#2-multi-thread-scanner)
  - [3. Sistema de Logging](#3-sistema-de-logging)
  - [4. Utilitários de Rede](#4-utilitários-de-rede)
  - [5. Módulo de Métricas](#5-módulo-de-métricas)
- [📊 Exemplos de Uso](#-exemplos-de-uso)
- [📈 Capacidades Técnicas](#-capacidades-técnicas)
- [📚 Bibliotecas Utilizadas](#-bibliotecas-utilizadas)
- [🔬 Dicas de Estudo](#-dicas-de-estudo)
- [🗺️ Roadmap de Desenvolvimento](#️-roadmap-de-desenvolvimento)
- [🤝 Como Contribuir](#-como-contribuir)
- [📄 Licença](#-licença)

---

## 📖 Sobre o Projeto

O **Python Security Toolkit** é um laboratório modular desenvolvido para estudo e experimentação de conceitos fundamentais de segurança cibernética utilizando Python. O projeto explora desde conceitos básicos de networking até técnicas avançadas de concorrência, logging profissional e processamento de dados.

### 🎯 Objetivos do Projeto

| Objetivo | Descrição |
|----------|-----------|
| **Educacional** | Fornecer material prático para estudo de segurança ofensiva/defensiva |
| **Técnico** | Demonstrar boas práticas de programação em Python |
| **Modular** | Criar arquitetura extensível para adicionar novas funcionalidades |
| **Documentado** | Manter código limpo com type hints, docstrings e exemplos |
| **Seguro** | Implementar validações robustas e tratamento de erros |

---

## 🎓 Contexto Acadêmico

Este projeto é desenvolvido como parte de estudos independentes em segurança cibernética, paralelamente ao bacharelado em **Engenharia Química na UFAL**. A interseção entre segurança digital e processos industriais (Indústria 4.0) motiva a exploração destes conceitos.

### Áreas de Estudo Abrangidas

- 🔐 **Segurança Ofensiva**: Reconhecimento, varredura de portas, fingerprinting
- 🛡️ **Segurança Defensiva**: Logging, monitoramento, validação de entradas
- 🌐 **Redes de Computadores**: Protocolos TCP/IP, sockets, concorrência
- 🐍 **Python Avançado**: Threading, decorators, context managers, type hints
- 📊 **Processamento de Dados**: JSON, CSV, estruturas de dados eficientes

---

## ⚠️ Aviso Legal

<div align="center">

| ⚠️ **ESTE É UM PROJETO EXCLUSIVAMENTE EDUCACIONAL** |
|-----------------------------------------------------|

</div>

### ✅ O que é PERMITIDO

- Utilizar em **ambientes controlados** (VMs, Docker, laboratórios locais)
- Estudar o código e aprender com a implementação
- Modificar e adaptar para **fins acadêmicos**
- Executar em redes **que você possui autorização explícita**
- Praticar em **CTFs, HackTheBox, TryHackMe**

### ❌ O que é PROIBIDO

- Utilizar contra sistemas **sem autorização explícita**
- Empregar em **atividades maliciosas ou criminosas**
- Executar em **ambientes de produção**
- Utilizar para **obter acesso não autorizado**
- **Remover avisos legais** ou atribuições

> **Responsabilidade**: O usuário assume TOTAL responsabilidade pelo uso desta ferramenta. O autor não se responsabiliza por qualquer dano direto ou indireto causado pelo uso inadequado.

---

## ⚙️ Funcionalidades Principais

### 📡 **Módulo de Scanner TCP**

| Funcionalidade | Descrição | Status |
|----------------|-----------|--------|
| Scanner TCP Básico | Varredura síncrona de portas | ✅ Concluído |
| Scanner Multi-Thread | Varredura assíncrona com threads | ✅ Concluído |
| Resolução de Hostnames | Suporte a domínios e IPs | ✅ Concluído |
| Timeout Configurável | Controle de latência | ✅ Concluído |
| Exportação de Resultados | JSON, CSV, TXT | ✅ Concluído |

### 📊 **Sistema de Logging**

| Funcionalidade | Descrição | Status |
|----------------|-----------|--------|
| Níveis de Log | DEBUG, INFO, WARNING, ERROR | ✅ Concluído |
| Output Colorido | Terminal com cores | ✅ Concluído |
| Log em Arquivo | Persistência de logs | ✅ Concluído |
| Formatação Estruturada | Timestamp, nível, mensagem | ✅ Concluído |

### 🔧 **Utilitários de Rede**

| Funcionalidade | Descrição | Status |
|----------------|-----------|--------|
| Validação de IP | IPv4/IPv6 com regex | ✅ Concluído |
| Validação de Porta | Range 1-65535 | ✅ Concluído |
| Parse de Ranges | CIDR, hifenizado, listas | ✅ Concluído |
| Resolução DNS | Forward/reverse lookup | 🔄 Em desenvolvimento |

### 📈 **Módulo de Métricas**

| Funcionalidade | Descrição | Status |
|----------------|-----------|--------|
| Tempo de Execução | Medição de performance | ✅ Concluído |
| Portas por Segundo | Taxa de varredura | ✅ Concluído |
| Estatísticas de Scan | Total de portas, abertas/fechadas | ✅ Concluído |
| Histórico de Operações | Registro de scans realizados | 🔄 Em desenvolvimento |

---

## 📦 Estrutura do Projeto

```

Automation-Toolkit/
│
├── 📁 base/                          # Módulos fundamentais
│   ├── init.py                   # Inicialização do pacote
│   ├── tcp_scanner_simple.py         # Scanner TCP básico
│   ├── multi_thread_scanner.py       # Scanner com threads
│   ├── logger.py                     # Sistema de logging profissional
│   ├── utils.py                      # Utilitários comuns
│   └── requirements.txt              # Dependências do projeto
│
├── 📁 recon/                         # Ferramentas de reconhecimento (em desenvolvimento)
│   ├── init.py
│   ├── dns_enum.py                   # Enumeração DNS
│   └── subdomain_finder.py           # Descoberta de subdomínios
│
├── 📁 exploits/                      # Módulos de exploração (planejado)
│   ├── init.py
│   ├── buffer_overflow.py            # Estudo de buffer overflow
│   └── sql_injection.py              # Automação SQLi
│
├── 📁 network/                       # Ferramentas de rede (planejado)
│   ├── init.py
│   ├── packet_craft.py               # Construção de pacotes
│   └── arp_spoof.py                  # ARP spoofing educacional
│
├── 📁 logs/                          # Diretório para arquivos de log
│   └── .gitkeep
│
├── 📁 outputs/                       # Resultados de scans e análises
│   └── .gitkeep
│
├── 📁 docs/                          # Documentação adicional
│   ├── examples.md                   # Exemplos detalhados
│   └── api_reference.md              # Referência de API
│
├── 📄 README.md                      # Documentação principal
├── 📄 LICENSE                        # Licença Apache 2.0
├── 📄 .gitignore                     # Arquivos ignorados pelo Git
└── 📄 index.html                     # Landing page oficial

```

---

## 🔧 Pré-requisitos

### 📋 Requisitos de Sistema

| Requisito | Especificação |
|-----------|---------------|
| **Sistema Operacional** | Linux, macOS, Windows (WSL recomendado) |
| **Python** | Versão 3.8 ou superior |
| **Pip** | Gerenciador de pacotes Python |
| **Privilégios** | Root/Admin para funcionalidades de rede avançadas |
| **Espaço em Disco** | Mínimo 50MB |

### 📦 Dependências

```txt
# base/requirements.txt

# Core dependencies
colorama==0.4.6              # Cores no terminal (Windows/Linux)
ipaddress==1.0.23            # Manipulação de endereços IP
typing-extensions==4.8.0     # Type hints avançados

# Optional (para funcionalidades futuras)
# scapy==2.5.0               # Manipulação de pacotes
# dnspython==2.4.2           # Enumeração DNS
# requests==2.31.0           # Requisições HTTP
# beautifulsoup4==4.12.2     # Parsing HTML
```

---

📥 Instalação

🐧 Linux / macOS / WSL

```bash
# 1. Clone o repositório
git clone https://github.com/Security-Labor/Automation-Toolkit.git
cd Automation-Toolkit

# 2. Crie um ambiente virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

# 3. Instale as dependências
pip install -r base/requirements.txt

# 4. Dê permissão de execução (opcional)
chmod +x base/*.py

# 5. Teste a instalação
python base/logger.py
```

🪟 Windows

```cmd
:: 1. Clone o repositório
git clone https://github.com/Security-Labor/Automation-Toolkit.git
cd Automation-Toolkit

:: 2. Crie um ambiente virtual
python -m venv venv
venv\Scripts\activate

:: 3. Instale as dependências
pip install -r base\requirements.txt

:: 4. Teste a instalação
python base\logger.py
```

🐳 Docker (Opcional)

```bash
# Construir imagem
docker build -t security-toolkit .

# Executar container interativo
docker run -it --rm security-toolkit /bin/bash
```

---

🛠️ Módulos e Ferramentas

1. TCP Scanner Simples

Scanner TCP básico para identificação de portas abertas. Ideal para estudo de sockets e conceitos fundamentais de rede.

📝 Sintaxe

```bash
python base/tcp_scanner_simple.py <target> [options]
```

⚙️ Parâmetros

Parâmetro Abreviação Descrição Default
target - IP ou hostname alvo Obrigatório
--ports -p Portas para escanear (ex: 80,443 ou 1-1000) 1-1024
--timeout -t Timeout em segundos 1.0
--output -o Arquivo de saída (.json ou .csv) None
--verbose -v Modo detalhado False

💡 Exemplos de Uso

```bash
# 1. Scan básico de portas comuns
python base/tcp_scanner_simple.py 192.168.1.1 -p 80,443,8080

# 2. Scan com range de portas e timeout reduzido
python base/tcp_scanner_simple.py 10.0.0.1 -p 1-500 -t 0.5

# 3. Scan com salvamento em JSON
python base/tcp_scanner_simple.py scanme.nmap.org -p 1-1000 -o resultado.json

# 4. Modo verbose para debug
python base/tcp_scanner_simple.py localhost -p 22,80,443 -v
```

📊 Exemplo de Saída

```
============================================================
RELATÓRIO DE SCAN - scanme.nmap.org (45.33.32.156)
============================================================
PORTA      SERVIÇO          STATUS    
------------------------------------------------------------
22         SSH              open      
80         HTTP             open      
443        HTTPS            open      
============================================================
Total de portas abertas: 3
Tempo total: 2.34 segundos
============================================================
```

---

2. Multi-Thread Scanner

Scanner de alta performance com suporte a múltiplas threads. Estudo de concorrência e paralelismo em Python.

📝 Sintaxe

```bash
python base/multi_thread_scanner.py <target> [options]
```

⚙️ Parâmetros

Parâmetro Abreviação Descrição Default
target - IP ou hostname alvo Obrigatório
--ports -p Portas para escanear 1-1024
--timeout -t Timeout em segundos 1.0
--threads -T Número de threads 100
--output -o Arquivo de saída (.json) None
--verbose -v Modo detalhado False

💡 Exemplos de Uso

```bash
# 1. Scan rápido com 200 threads
python base/multi_thread_scanner.py 192.168.1.1 -p 1-1000 -T 200 -v

# 2. Scan completo com salvamento
python base/multi_thread_scanner.py target.com -p 1-65535 -o full_scan.json -T 500

# 3. Scan com timeout reduzido para rede rápida
python base/multi_thread_scanner.py 10.0.0.1 -p 1-10000 -t 0.3 -T 300
```

📊 Exemplo de Saída JSON

```json
{
  "target": "192.168.1.1",
  "scan_date": "2026-03-29 10:30:22",
  "total_ports_scanned": 1000,
  "total_open_ports": 5,
  "scan_time_seconds": 1.87,
  "ports_per_second": 534.76,
  "open_ports": [
    {"port": 22, "service": "SSH", "banner": "OpenSSH 8.2p1"},
    {"port": 80, "service": "HTTP", "banner": "nginx/1.18.0"},
    {"port": 443, "service": "HTTPS", "banner": "nginx/1.18.0"},
    {"port": 3306, "service": "MySQL", "banner": "MySQL 8.0.23"},
    {"port": 8080, "service": "HTTP-Alt", "banner": "Apache Tomcat"}
  ]
}
```

---

3. Sistema de Logging

Sistema profissional de logging com suporte a cores, múltiplos níveis e saída em arquivo.

📝 Uso Programático

```python
from base.logger import setup_logger

# Configurar logger
logger = setup_logger(
    name="my_scanner",
    log_file="logs/scan.log",
    level="INFO"
)

# Exemplos de uso
logger.debug("Mensagem de debug (não exibida)")
logger.info("Scan iniciado no alvo 192.168.1.1")
logger.warning("Timeout excedido para porta 9999")
logger.error("Falha na resolução DNS")
```

🎨 Níveis de Log

Nível Cor Uso
DEBUG 🔵 Azul Informações detalhadas para debug
INFO 🟢 Verde Operações normais e progresso
WARNING 🟡 Amarelo Situações potencialmente problemáticas
ERROR 🔴 Vermelho Erros que não interrompem execução
CRITICAL 🟣 Magenta Erros fatais que interrompem execução

---

4. Utilitários de Rede

Funções utilitárias para manipulação de redes e validação de dados.

📝 API de Utilitários

```python
from base.utils import (
    validate_ip,
    validate_port,
    parse_ip_range,
    parse_ports,
    get_service_name,
    sanitize_filename
)

# Validação de IP
validate_ip("192.168.1.1")      # True
validate_ip("999.999.999.999")  # False

# Validação de porta
validate_port(80)   # True
validate_port(0)    # False
validate_port(70000) # False

# Parse de ranges
ips = parse_ip_range("192.168.1.1-10, 10.0.0.0/30")
# Resultado: ['192.168.1.1', '192.168.1.2', ...]

# Parse de portas
ports = parse_ports("1-100, 443, 8080-8082")
# Resultado: [1, 2, 3, ..., 100, 443, 8080, 8081, 8082]

# Identificação de serviço por porta
get_service_name(22)   # "SSH"
get_service_name(80)   # "HTTP"
get_service_name(443)  # "HTTPS"

# Sanitização de nome de arquivo
sanitize_filename("../../../etc/passwd")  # "etc_passwd"
```

---

5. Módulo de Métricas

Sistema de métricas para monitoramento de performance.

📝 Uso Programático

```python
from base.metrics import MetricsTracker

# Inicializar tracker
tracker = MetricsTracker()

# Registrar início de operação
tracker.start_scan("192.168.1.1", total_ports=1000)

# Simular scan...
tracker.record_open_port(22)
tracker.record_open_port(80)

# Finalizar e obter métricas
stats = tracker.end_scan()
print(f"Tempo: {stats['duration']:.2f}s")
print(f"Portas/segundo: {stats['pps']:.2f}")
print(f"Portas abertas: {stats['open_ports']}")
```

📊 Exemplo de Saída

```
📊 MÉTRICAS DO SCAN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Alvo: 192.168.1.1
Portas escaneadas: 1000
Portas abertas: 5
Tempo total: 1.87s
Portas/segundo: 534.76
Eficiência: 99.8%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

📊 Exemplos de Uso

🔬 Exemplo 1: Laboratório Local

```bash
# Cenário: Estudar comportamento de portas em VM local

# 1. Iniciar VM com Metasploitable 2 (IP: 192.168.122.100)
# 2. Executar scan básico
python base/tcp_scanner_simple.py 192.168.122.100 -p 1-1000 -v

# 3. Scan completo com multi-thread
python base/multi_thread_scanner.py 192.168.122.100 -p 1-65535 -T 300 -o metasploitable.json

# 4. Analisar resultados
cat metasploitable.json | jq '.open_ports[] | {port, service}'
```

🎯 Exemplo 2: CTF / HackTheBox

```bash
# Cenário: Reconhecimento inicial em máquina CTF

# 1. Scan rápido de portas comuns
python base/multi_thread_scanner.py 10.10.10.100 -p 1-1000 -T 200 -v

# 2. Scan detalhado das portas encontradas
python base/tcp_scanner_simple.py 10.10.10.100 -p 22,80,8080,3306 -t 0.5 -v

# 3. Exportar resultados para análise
python base/multi_thread_scanner.py 10.10.10.100 -p 1-10000 -T 200 -o ctf_results.json
```

📚 Exemplo 3: Estudo de Concorrência

```python
# benchmark.py - Comparação de performance

import time
from base.tcp_scanner_simple import TCPScannerSimple
from base.multi_thread_scanner import MultiThreadScanner

# Teste com scanner simples
start = time.time()
simple = TCPScannerSimple("127.0.0.1", ports=range(1, 1001))
simple.scan()
simple_time = time.time() - start

# Teste com scanner multi-thread
start = time.time()
multi = MultiThreadScanner("127.0.0.1", ports=range(1, 1001), threads=100)
multi.scan()
multi_time = time.time() - start

print(f"Scanner Simples: {simple_time:.2f}s")
print(f"Multi-Thread: {multi_time:.2f}s")
print(f"Speedup: {simple_time / multi_time:.2f}x")
```

---

📈 Capacidades Técnicas

🚀 Performance

Métrica Valor Descrição
Máximo de Threads 1000+ Limitado pelo sistema operacional
Portas por Segundo ~5000 Em rede local com bom desempenho
Timeout Mínimo 0.1s Configurável conforme necessidade
Memória por Thread ~8MB Aproximadamente
Escala Máxima 65535 portas Todo o espaço de portas TCP

🔒 Limitações de Segurança

Limitação Descrição
Portas Privilegiadas Portas < 1024 requerem root/Admin
Firewalls Podem bloquear ou limitar scans
Rate Limiting Sistemas podem detectar scans agressivos
IDS/IPS Scans podem ser detectados e bloqueados

🌐 Compatibilidade

Protocolo Suporte
IPv4 ✅ Completo
IPv6 ✅ Parcial (em desenvolvimento)
TCP ✅ Completo
UDP 🔄 Em desenvolvimento
ICMP 🔄 Em desenvolvimento

---

📚 Bibliotecas Utilizadas

🔧 Bibliotecas Core

Biblioteca Versão Uso
socket built-in Comunicação TCP/IP
threading built-in Concorrência e paralelismo
ipaddress built-in Manipulação de endereços IP
json built-in Serialização de dados
csv built-in Exportação para CSV
argparse built-in Parsing de argumentos CLI
logging built-in Sistema de logs
time built-in Temporização e métricas
re built-in Expressões regulares
pathlib built-in Manipulação de caminhos

🎨 Bibliotecas Opcionais

Biblioteca Versão Uso
colorama 0.4.6 Cores no terminal (Windows)
scapy 2.5.0 Manipulação avançada de pacotes
dnspython 2.4.2 Enumeração DNS
requests 2.31.0 Requisições HTTP
beautifulsoup4 4.12.2 Parsing HTML

---

🔬 Dicas de Estudo

🎓 Para Iniciantes em Segurança

1. Comece pelo básico
   ```bash
   # Entenda como um scanner TCP funciona
   python base/tcp_scanner_simple.py localhost -p 1-100 -v
   ```
2. Estude o código fonte
   · Leia tcp_scanner_simple.py linha por linha
   · Entenda como os sockets funcionam
   · Experimente modificar o timeout
3. Monte um laboratório local
   · Instale VirtualBox/VMware
   · Baixe máquinas vulneráveis (Metasploitable, DVWA)
   · Pratique em ambiente isolado

🚀 Para Desenvolvedores

1. Estude a arquitetura
   · Explore a modularidade do código
   · Adicione novas funcionalidades como plugins
2. Melhore a performance
   · Experimente diferentes números de threads
   · Implemente scanner UDP
   · Adicione sistema de retry
3. Implemente novas features
   · Banner grabbing
   · Service detection
   · OS fingerprinting

🔬 Para Pesquisadores

1. Analise padrões de rede
   · Use Wireshark para capturar pacotes
   · Estude o handshake TCP
   · Analise o impacto de diferentes timeouts
2. Compare ferramentas
   · Compare com Nmap, Masscan, Zmap
   · Analise vantagens e desvantagens
3. Documente descobertas
   · Crie relatórios técnicos
   · Publique artigos sobre suas experiências

---


🤝 Como Contribuir

Contribuições são muito bem-vindas! Este é um projeto educacional e toda ajuda é apreciada.

📋 Tipos de Contribuição

Tipo Descrição
🐛 Bug Reports Reporte problemas encontrados
💡 Sugestões Ideias para novas funcionalidades
📝 Documentação Melhorias na documentação
🔧 Código Correções e novas features
🎓 Exemplos Novos casos de uso e tutoriais

🔄 Fluxo de Contribuição

```bash
# 1. Fork o projeto
# 2. Clone seu fork
git clone https://github.com/seu-usuario/Automation-Toolkit.git
cd Automation-Toolkit

# 3. Crie uma branch para sua contribuição
git checkout -b feature/minha-feature

# 4. Faça suas alterações
# - Adicione type hints
# - Documente com docstrings
# - Siga PEP 8
# - Inclua exemplos de uso

# 5. Teste suas alterações
python base/tcp_scanner_simple.py localhost -p 22 -v

# 6. Commit e push
git add .
git commit -m "feat: descrição clara da alteração"
git push origin feature/minha-feature

# 7. Abra um Pull Request
```

📝 Padrões de Código

```python
# ✅ Boas práticas

def minha_funcao(parametro: str, opcional: int = 10) -> List[str]:
    """
    Descrição clara da função.

    Args:
        parametro: Descrição do parâmetro obrigatório
        opcional: Descrição do parâmetro opcional (default: 10)

    Returns:
        Lista de strings com os resultados

    Examples:
        >>> minha_funcao("exemplo")
        ['resultado1', 'resultado2']
    """
    # Implementação
    pass
```



📄 Licença

Distribuído sob a licença Apache 2.0. Veja o arquivo LICENSE para mais informações.

```
Copyright 2024 URSA UNIVERSITY

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

📞 Contato e Suporte

Canal Link
GitHub Issues Abrir Issue
Email suporteursauniversity.tech@gmail.com
Landing Page security-labor.github.io/Automation-Toolkit

---

<div align="center">

⭐️ Se este projeto foi útil para seus estudos, considere dar uma estrela! ⭐️

"A segurança é uma jornada, não um destino."

🔬 Desenvolvido com 🐍 para fins educacionais

</div>
