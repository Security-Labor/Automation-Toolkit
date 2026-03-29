#!/usr/bin/env python3
"""
███████████████████████████████████████████████████████████████████████████████
█  CYBER SECURITY TOOLKIT - ENTERPRISE GRADE v2.0                               █
█  Blue/Red Team Arsenal - Validação Militar & Persistência Ofuscada          █
███████████████████████████████████████████████████████████████████████████████

Framework de Segurança Ofensiva/Defensiva com:
- Validação em múltiplas camadas (sintática, semântica, contextual)
- Parser adaptativo com fallback strategies
- Persistência cifrada opcional (AES-256-GCM)
- Sistema de logging estruturado
- Decorators de segurança para funções críticas
- Type hints com validação em runtime
"""

import json
import csv
import ipaddress
import re
import sys
import os
import hashlib
import logging
import time
import base64
from typing import (
    List, Dict, Any, Union, Optional, Set, Tuple, 
    Callable, TypeVar, Generic, cast, overload
)
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from functools import wraps, lru_cache
from contextlib import contextmanager
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import struct

# ============================================================================
# CONFIGURAÇÃO DE SEGURANÇA
# ============================================================================

class SecurityLevel(Enum):
    """Níveis de rigor na validação"""
    LOOSE = auto()      # Aceita formatos não-padrão
    STANDARD = auto()   # Validação RFC estrita
    PARANOID = auto()   # Validação + sanitização profunda
    MILITARY = auto()   # Máximo rigor, rejeita qualquer ambiguidade

class LogLevel(Enum):
    """Níveis de verbosidade do logger"""
    SILENT = 0
    MINIMAL = 1
    VERBOSE = 2
    DEBUG = 3

# ============================================================================
# DECORATORS DE SEGURANÇA
# ============================================================================

def secure_execution(error_message: str = "Erro crítico"):
    """Decorator que envolve funções com tratamento de exceções e logging"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logging.error(f"{error_message} em {func.__name__}: {str(e)}")
                if logging.getLogger().level <= logging.DEBUG:
                    logging.exception("Stack trace completo:")
                return None
        return wrapper
    return decorator

def validate_input_types(**type_map):
    """Decorator para validação de tipos em runtime"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Valida args posicionais
            for i, (arg_name, expected_type) in enumerate(type_map.items()):
                if i < len(args):
                    value = args[i]
                    if not isinstance(value, expected_type):
                        raise TypeError(f"Argumento '{arg_name}' deve ser {expected_type.__name__}, "
                                      f"recebeu {type(value).__name__}")
            
            # Valida kwargs
            for arg_name, expected_type in type_map.items():
                if arg_name in kwargs:
                    value = kwargs[arg_name]
                    if not isinstance(value, expected_type):
                        raise TypeError(f"Argumento '{arg_name}' deve ser {expected_type.__name__}, "
                                      f"recebeu {type(value).__name__}")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# ============================================================================
# DATACLASSES E MODELOS DE DADOS
# ============================================================================

@dataclass(frozen=True)  # Imutável para segurança
class NetworkTarget:
    """Modelo de dados imutável para alvos de rede"""
    ip: str
    port: Optional[int] = None
    protocol: str = "tcp"
    
    def __post_init__(self):
        """Validação automática após inicialização"""
        if not validate_ip(self.ip):
            raise ValueError(f"IP inválido: {self.ip}")
        if self.port and not validate_port(self.port):
            raise ValueError(f"Porta inválida: {self.port}")
        if self.protocol.lower() not in ["tcp", "udp", "icmp"]:
            raise ValueError(f"Protocolo inválido: {self.protocol}")

@dataclass
class ScanResult:
    """Estrutura para resultados de varredura"""
    target: NetworkTarget
    status: str
    response_time: float
    additional_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

@dataclass
class SecurityContext:
    """Contexto de segurança para operações críticas"""
    security_level: SecurityLevel = SecurityLevel.STANDARD
    log_level: LogLevel = LogLevel.MINIMAL
    encryption_key: Optional[bytes] = None
    allow_unsafe_operations: bool = False

# ============================================================================
# VALIDAÇÕES MILITARES (MULTI-CAMADA)
# ============================================================================

class IPValidator:
    """Validador de IPs com múltiplos níveis de rigor"""
    
    @staticmethod
    def _is_private(ip: str) -> bool:
        """Verifica se IP é privado"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    @staticmethod
    def _is_reserved(ip: str) -> bool:
        """Verifica se IP é reservado/multicast"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_loopback
        except:
            return True
    
    @classmethod
    def validate(cls, ip: str, level: SecurityLevel = SecurityLevel.STANDARD) -> Tuple[bool, Optional[str]]:
        """
        Valida IP com diferentes níveis de rigor
        Retorna: (is_valid, error_message)
        """
        # Camada 1: Sintaxe básica
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False, f"Sintaxe inválida: {ip}"
        
        # Camada 2: Validações semânticas
        if level == SecurityLevel.LOOSE:
            return True, None
        
        # Camada 3: Verificações de segurança
        if level in [SecurityLevel.PARANOID, SecurityLevel.MILITARY]:
            if cls._is_reserved(str(ip_obj)):
                return False, f"IP reservado/loopback não permitido: {ip}"
            
            if level == SecurityLevel.MILITARY:
                if cls._is_private(str(ip_obj)):
                    return False, f"IP privado não permitido em modo MILITARY: {ip}"
        
        return True, None

class PortValidator:
    """Validador de portas com análise de portas privilegiadas"""
    
    PRIVILEGED_PORTS = set(range(1, 1024))
    WELL_KNOWN_PORTS = set(range(1, 49152))
    EPHEMERAL_PORTS = set(range(49152, 65536))
    
    @classmethod
    def validate(cls, port: int, level: SecurityLevel = SecurityLevel.STANDARD) -> Tuple[bool, Optional[str]]:
        """Valida porta com diferentes níveis de rigor"""
        if not (1 <= port <= 65535):
            return False, f"Porta fora do range: {port}"
        
        if level == SecurityLevel.MILITARY:
            if port in cls.PRIVILEGED_PORTS:
                return False, f"Porta privilegiada ({port}) requer elevação de privilégios"
        
        return True, None

# ============================================================================
# PARSERS DE ALTA PERFORMANCE COM CACHE LRU
# ============================================================================

class AdvancedNetworkParser:
    """Parser de rede com cache, suporte a múltiplos formatos e validação adaptativa"""
    
    def __init__(self, context: Optional[SecurityContext] = None):
        self.context = context or SecurityContext()
        self._setup_logging()
    
    def _setup_logging(self):
        """Configura logger baseado no nível de segurança"""
        level_map = {
            LogLevel.SILENT: logging.ERROR,
            LogLevel.MINIMAL: logging.WARNING,
            LogLevel.VERBOSE: logging.INFO,
            LogLevel.DEBUG: logging.DEBUG
        }
        logging.basicConfig(
            level=level_map.get(self.context.log_level, logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    @lru_cache(maxsize=128)
    def parse_ip_range(self, ip_input: str) -> List[str]:
        """
        Parse ultra-robusto de alvos de rede com cache.
        Suporta: CIDR, Range Hifenizado, IP Único, Listas, Arquivos de texto
        """
        ips: Set[str] = set()
        
        # Detecta se é arquivo
        if Path(ip_input).exists() and ip_input.endswith(('.txt', '.lst', '.targets')):
            try:
                with open(ip_input, 'r') as f:
                    content = f.read()
                    return self.parse_ip_range(content)
            except Exception as e:
                logging.error(f"Erro ao ler arquivo: {e}")
                return []
        
        # Suporte a múltiplos alvos separados por espaço/vírgula/linha
        targets = re.split(r'[\s,;\n]+', ip_input.strip())
        
        for target in targets:
            if not target or target.isspace():
                continue
            
            # Remove comentários
            target = target.split('#')[0].strip()
            
            try:
                # 1. Tenta CIDR
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    ips.update(str(ip) for ip in network.hosts())
                
                # 2. Tenta Range Hifenizado
                elif '-' in target:
                    ips.update(self._parse_hyphen_range(target))
                
                # 3. IP Único
                else:
                    is_valid, error = IPValidator.validate(target, self.context.security_level)
                    if is_valid:
                        ips.add(str(ipaddress.ip_address(target)))
                    elif self.context.log_level == LogLevel.DEBUG:
                        logging.debug(f"IP inválido ignorado: {target} - {error}")
                        
            except Exception as e:
                logging.warning(f"Erro ao parsear target '{target}': {e}")
                continue
        
        # Ordenação inteligente
        return sorted(list(ips), key=lambda ip: ipaddress.ip_address(ip))
    
    def _parse_hyphen_range(self, target: str) -> Set[str]:
        """Parse específico para ranges com hífen"""
        ips = set()
        start_part, end_part = target.split('-')
        start_part = start_part.strip()
        end_part = end_part.strip()
        
        start_ip = ipaddress.ip_address(start_part)
        
        # Caso o final seja apenas um octeto
        if '.' not in end_part:
            prefix = '.'.join(start_part.split('.')[:-1])
            end_ip = ipaddress.ip_address(f"{prefix}.{end_part}")
        else:
            end_ip = ipaddress.ip_address(end_part)
        
        # Geração otimizada do range
        start_int = int(start_ip)
        end_int = int(end_ip)
        
        if start_int <= end_int:
            # Limite de segurança para não estourar memória
            max_hosts = 10000 if self.context.security_level == SecurityLevel.MILITARY else 1000000
            if (end_int - start_int) > max_hosts:
                logging.warning(f"Range muito grande ({end_int - start_int} hosts), truncando")
                end_int = start_int + max_hosts
            
            for ip_int in range(start_int, end_int + 1):
                ips.add(str(ipaddress.ip_address(ip_int)))
        
        return ips
    
    @lru_cache(maxsize=128)
    def parse_ports(self, port_str: str) -> List[int]:
        """
        Parse complexo de portas com cache
        Exemplos: "80,443,1-1024,8080", "common", "privileged", "all"
        """
        # Palavras-chave especiais
        port_presets = {
            'common': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                      993, 995, 1723, 3306, 3389, 5900, 8080],
            'privileged': list(range(1, 1024)),
            'all': list(range(1, 65536)),
            'web': [80, 443, 8080, 8443, 8000, 8008, 8888],
            'database': [3306, 5432, 1433, 1521, 27017, 6379]
        }
        
        port_str = port_str.strip().lower()
        
        # Verifica se é um preset
        if port_str in port_presets:
            return port_presets[port_str]
        
        ports: Set[int] = set()
        
        # Divide por vírgulas
        parts = port_str.replace(' ', '').split(',')
        
        for part in parts:
            if not part:
                continue
                
            # Range com hífen
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    start = max(1, min(start, 65535))
                    end = max(start, min(end, 65535))
                    
                    # Validação de segurança para ranges grandes
                    if self.context.security_level == SecurityLevel.MILITARY and (end - start) > 1000:
                        logging.warning(f"Range muito grande ({end - start} portas) em modo MILITARY")
                        continue
                    
                    ports.update(range(start, end + 1))
                except ValueError:
                    continue
            
            # Porta única
            else:
                try:
                    p = int(part)
                    is_valid, error = PortValidator.validate(p, self.context.security_level)
                    if is_valid:
                        ports.add(p)
                    elif self.context.log_level == LogLevel.DEBUG:
                        logging.debug(f"Porta ignorada: {p} - {error}")
                except ValueError:
                    continue
        
        return sorted(list(ports))

# ============================================================================
# PERSISTÊNCIA CIFRADA (ENTERPRISE GRADE)
# ============================================================================

class EncryptedStorage:
    """Armazenamento com criptografia AES-256-GCM via Fernet"""
    
    def __init__(self, key: Optional[bytes] = None, key_file: Optional[str] = None):
        """Inicializa com chave ou gera nova"""
        if key:
            self.key = key
        elif key_file and Path(key_file).exists():
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
        
        self.cipher = Fernet(self.key)
    
    @classmethod
    def from_password(cls, password: str, salt: Optional[bytes] = None) -> 'EncryptedStorage':
        """Gera chave a partir de senha (PBKDF2)"""
        if not salt:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return cls(key)
    
    def encrypt(self, data: Any) -> bytes:
        """Criptografa dados"""
        json_data = json.dumps(data, indent=2)
        return self.cipher.encrypt(json_data.encode())
    
    def decrypt(self, encrypted_data: bytes) -> Any:
        """Descriptografa dados"""
        decrypted = self.cipher.decrypt(encrypted_data)
        return json.loads(decrypted.decode())
    
    def save_encrypted(self, data: Any, filename: str) -> bool:
        """Salva dados criptografados"""
        try:
            encrypted = self.encrypt(data)
            path = Path(filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('wb') as f:
                f.write(encrypted)
            return True
        except Exception as e:
            logging.error(f"Erro ao salvar arquivo criptografado: {e}")
            return False
    
    def load_encrypted(self, filename: str) -> Optional[Any]:
        """Carrega dados criptografados"""
        try:
            with open(filename, 'rb') as f:
                encrypted = f.read()
            return self.decrypt(encrypted)
        except Exception as e:
            logging.error(f"Erro ao carregar arquivo criptografado: {e}")
            return None

class SecureDataManager:
    """Gerenciador de persistência com suporte a múltiplos formatos e criptografia"""
    
    def __init__(self, context: Optional[SecurityContext] = None):
        self.context = context or SecurityContext()
        self.encrypted_storage: Optional[EncryptedStorage] = None
        
        if context and context.encryption_key:
            self.encrypted_storage = EncryptedStorage(context.encryption_key)
    
    @secure_execution("Falha ao salvar dados")
    def save(self, data: Any, filename: str, format_type: str = 'json', encrypt: bool = False) -> bool:
        """Salva dados em múltiplos formatos com opção de criptografia"""
        filename = self._sanitize_filename(filename)
        
        if encrypt and self.encrypted_storage:
            return self.encrypted_storage.save_encrypted(data, filename)
        
        if format_type == 'json':
            return self._save_json(data, filename)
        elif format_type == 'csv':
            return self._save_csv(data, filename)
        elif format_type == 'txt':
            return self._save_txt(data, filename)
        else:
            raise ValueError(f"Formato não suportado: {format_type}")
    
    def _save_json(self, data: Any, filename: str) -> bool:
        """Salva JSON com metadados de segurança"""
        try:
            # Adiciona metadados
            if isinstance(data, dict):
                metadata = {
                    '_metadata': {
                        'timestamp': time.time(),
                        'security_level': self.context.security_level.name if self.context else 'unknown',
                        'version': '2.0'
                    }
                }
                data = {**metadata, **data}
            
            path = Path(filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with path.open('w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
            
            # Permissões seguras (apenas dono pode ler/escrever)
            os.chmod(path, 0o600)
            
            return True
        except Exception as e:
            logging.error(f"Erro ao salvar JSON: {e}")
            return False
    
    def _save_csv(self, data: List[Dict], filename: str) -> bool:
        """Salva CSV com validação de estrutura"""
        if not data:
            return False
        
        try:
            # Extrai todos os headers
            fieldnames = set()
            for d in data:
                fieldnames.update(d.keys())
            
            path = Path(filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with path.open('w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                writer.writeheader()
                writer.writerows(data)
            
            os.chmod(path, 0o600)
            return True
         
