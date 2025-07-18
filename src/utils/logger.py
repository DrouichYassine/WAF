"""
Logging utility for WAF.
"""

import os
import logging
import logging.handlers
import time

def setup_logging(level='INFO', log_file=None):
    """
    Set up logging for the WAF application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
    """
    # Create logger
    logger = logging.getLogger('waf')
    logger.setLevel(getattr(logging, level))
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if log file is specified
    if log_file:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Use rotating file handler to manage log size
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10485760, backupCount=5  # 10MB max size, keep 5 backups
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Create security logger for recording security events
    security_logger = logging.getLogger('waf.security')
    security_logger.setLevel(logging.INFO)
    
    # If log file is specified, create a separate security log file
    if log_file:
        security_log_file = os.path.join(
            os.path.dirname(log_file),
            'security_' + os.path.basename(log_file)
        )
        security_handler = logging.handlers.RotatingFileHandler(
            security_log_file, maxBytes=10485760, backupCount=5
        )
        security_handler.setFormatter(formatter)
        security_logger.addHandler(security_handler)
    
    logger.info(f"Logging initialized at level {level}")