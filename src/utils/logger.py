# Utilitaire de journalisation pour WAF.


import os
import logging
import logging.handlers
import time

def setup_logging(level='INFO', log_file=None):
    """
    Configure la journalisation pour l'application WAF.
    
    Args:
        level: Niveau de journalisation (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Chemin vers le fichier de log (optionnel)
    """
    # Créer le logger
    logger = logging.getLogger('waf')
    logger.setLevel(getattr(logging, level))
    
    # Créer le formateur
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Créer le gestionnaire de console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Créer le gestionnaire de fichier si un fichier de log est spécifié
    if log_file:
        # Créer le répertoire s'il n'existe pas
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Utiliser un gestionnaire de fichiers rotatif pour gérer la taille du log
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10485760, backupCount=5  # Taille max 10Mo, garder 5 sauvegardes
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Créer un logger de sécurité pour enregistrer les événements de sécurité
    security_logger = logging.getLogger('waf.security')
    security_logger.setLevel(logging.INFO)
    
    # Si un fichier de log est spécifié, créer un fichier de log de sécurité séparé
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