
# Gestionnaire de configuration pour WAF.


import os
import json
import yaml
import logging

class ConfigManager:
    # Charger et gérer les configurations du WAF.
    
    def __init__(self, config_path):
        # Initialiser avec le chemin du fichier de configuration.
        self.config_path = config_path
        self.logger = logging.getLogger('waf.config')
    
    def load_config(self):
        # Charger la configuration depuis le fichier.
        if not os.path.exists(self.config_path):
            self.logger.error(f"Configuration file not found: {self.config_path}")
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        try:
            file_ext = os.path.splitext(self.config_path)[1].lower()
            
            if file_ext == '.json':
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
            
            elif file_ext in ['.yaml', '.yml', '.conf']:  # Ajout du support .conf
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
            
            else:
                self.logger.error(f"Unsupported configuration file format: {file_ext}")
                raise ValueError(f"Unsupported configuration file format: {file_ext}")
            
            self._validate_config(config)
            return config
        
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {str(e)}")
            raise
    
    def _validate_config(self, config):
        # Valider la configuration chargée.
        required_fields = ['listen_port', 'rules_path', 'log_path']
        
        for field in required_fields:
            if field not in config:
                self.logger.error(f"Missing required configuration field: {field}")
                raise ValueError(f"Missing required configuration field: {field}")
        
        return True