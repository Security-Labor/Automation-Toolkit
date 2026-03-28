#!/usr/bin/env python3
"""
Módulo de logging para ferramentas de segurança
Suporte a múltiplos níveis, cores e saída em arquivo
"""

import logging
import sys
from datetime import datetime
from pathlib import Path

# Cores para terminal (ANSI)
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'

class ColoredFormatter(logging.Formatter):
    """Formatter personalizado com cores para diferentes níveis"""
    
    COLORS = {
        'DEBUG': Colors.GRAY,
        'INFO': Colors.GREEN,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.RED + Colors.BLUE,
    }
    
    def format(self, record):
        log_message = super().format(record)
        color = self.COLORS.get(record.levelname, Colors.RESET)
        return f"{color}{log_message}{Colors.RESET}"

def setup_logger(name: str, log_file: str = None, verbose: bool = True):
    """
    Configura logger com saída para console e arquivo
    
    Args:
        name: Nome do logger
        log_file: Caminho do arquivo de log (opcional)
        verbose: Nível detalhado (True = DEBUG, False = INFO)
    
    Returns:
        logger configurado
    """
    logger = logging.getLogger(name)
    
    # Evita duplicação de handlers
    if logger.handlers:
        return logger
    
    # Define nível base
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    
    # Formato padrão
    format_str = '%(asctime)s | %(levelname)-8s | %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Handler para console com cores
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_format = ColoredFormatter(format_str, date_format)
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # Handler para arquivo (se especificado)
    if log_file:
        # Cria diretório se não existir
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(format_str, date_format)
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger

# Logger global para ferramentas
tool_logger = setup_logger('security_toolkit', 'logs/toolkit.log')

if __name__ == '__main__':
    # Teste do logger
    logger = setup_logger('test', verbose=True)
    logger.debug("Mensagem de debug (apenas verbose)")
    logger.info("Informação geral")
    logger.warning("Aviso importante")
    logger.error("Erro crítico")
    logger.critical("Falha catastrófica")
