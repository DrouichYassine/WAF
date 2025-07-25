#Module de chargement des règles pour charger et analyser les règles WAF.


import os
import json
import yaml
import re
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class Rule:
    #Définition d'une règle WAF.
    id: str
    name: str
    description: str
    tags: List[str]
    priority: str
    match_patterns: List[Dict[str, Any]]
    actions: List[str]
    enabled: bool = True

class RuleLoader:
    #Charger et analyser les règles WAF à partir de fichiers.

    def __init__(self, rules_path):
        #Initialiser avec le chemin du répertoire des règles.
        self.rules_path = rules_path
        self.logger = logging.getLogger('waf.rules')
    
    def load_rules(self):
        #Charger toutes les règles depuis le répertoire des règles.
        rules = []
        
        if not os.path.exists(self.rules_path):
            self.logger.error(f"Rules directory not found: {self.rules_path}")
            raise FileNotFoundError(f"Rules directory not found: {self.rules_path}")
        
        # Si rules_path est un répertoire, charger tous les fichiers de règles
        if os.path.isdir(self.rules_path):
            for filename in os.listdir(self.rules_path):
                if filename.endswith(('.json', '.yaml', '.yml')):
                    file_path = os.path.join(self.rules_path, filename)
                    rules.extend(self._load_rule_file(file_path))
        
        # Si rules_path est un fichier, charger uniquement ce fichier
        elif os.path.isfile(self.rules_path):
            rules.extend(self._load_rule_file(self.rules_path))
        
        self.logger.info(f"{len(rules)} WAF rules loaded")
        return rules
    
    def _load_rule_file(self, file_path):
        #Charger les règles à partir d'un seul fichier.
        try:
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext == '.json':
                with open(file_path, 'r') as f:
                    rule_data = json.load(f)
            
            elif file_ext in ['.yaml', '.yml']:
                with open(file_path, 'r') as f:
                    rule_data = yaml.safe_load(f)
            
            else:
                self.logger.warning(f"Unsupported rule file format: {file_ext}")
                return []
            
            rules = self._parse_rules(rule_data, file_path)
            self.logger.debug(f"{len(rules)} rules loaded from {file_path}")
            return rules
        
        except Exception as e:
            self.logger.error(f"Failed to load rule file {file_path}: {str(e)}")
            return []
    
    def _parse_rules(self, rule_data, file_path):
        #Analyser les données de règles chargées en objets Rule.
        rules = []
        
        if isinstance(rule_data, list):
            for item in rule_data:
                rule = self._parse_rule(item, file_path)
                if rule:
                    rules.append(rule)
        
        elif isinstance(rule_data, dict):
            if 'rules' in rule_data and isinstance(rule_data['rules'], list):
                for item in rule_data['rules']:
                    rule = self._parse_rule(item, file_path)
                    if rule:
                        rules.append(rule)
            else:
                rule = self._parse_rule(rule_data, file_path)
                if rule:
                    rules.append(rule)
        
        return rules
    
    def _parse_rule(self, rule_data, file_path):
        #Analyser une seule règle à partir des données.
        try:
            # Valider les champs obligatoires
            required_fields = ['id', 'match']
            for field in required_fields:
                if field not in rule_data:
                    self.logger.warning(f"Règle dans {file_path} sans champ obligatoire : {field}")
                    return None
            
            # Compiler les motifs regex
            match_patterns = []
            match_data = rule_data['match']
            
            if isinstance(match_data, list):
                for match in match_data:
                    self._compile_pattern(match)
                    match_patterns.append(match)
            else:
                self._compile_pattern(match_data)
                match_patterns = [match_data]
            
            # Créer l'objet Rule
            rule = Rule(
                id=rule_data['id'],
                name=rule_data.get('name', rule_data['id']),
                description=rule_data.get('description', ''),
                tags=rule_data.get('tags', []),
                priority=rule_data.get('priority', 'medium'),
                match_patterns=match_patterns,
                actions=rule_data.get('actions', ['block']),
                enabled=rule_data.get('enabled', True)
            )
            
            return rule
        
        except Exception as e:
            self.logger.error(f"Failed to parse rule in {file_path}: {str(e)}")
            return None
    
    def _compile_pattern(self, match_data):
        #Compiler le motif regex dans les données de correspondance.
        if 'pattern' in match_data and isinstance(match_data['pattern'], str):
            try:
                match_data['compiled_pattern'] = re.compile(match_data['pattern'])
            except re.error as e:
                self.logger.error(f"Invalid regex pattern '{match_data['pattern']}': {str(e)}")
                match_data['compiled_pattern'] = None