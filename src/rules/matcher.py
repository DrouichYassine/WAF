#Module de correspondance de règles pour appliquer les règles WAF aux requêtes HTTP.


import logging
import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class MatchResult:
    # Résultat d'une opération de correspondance de règle.
    blocked: bool = False
    rule_id: Optional[str] = None
    reason: Optional[str] = None
    actions: List[str] = None

class RuleMatcher:
    # Applique les règles WAF aux requêtes HTTP.

    def __init__(self, rules):
        # Initialise avec une liste de règles WAF.
        self.rules = rules
        self.logger = logging.getLogger('waf.matcher')
    
    def match_request(self, request_data):
        """
        Applique toutes les règles à la requête et retourne le résultat.
        
        Args:
            request_data: Dictionnaire contenant les données HTTP de la requête analysée
            
        Returns:
            MatchResult: Résultat de l'opération de correspondance de règle
        """
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            result = self._match_rule(rule, request_data)
            if result.blocked:
                return result
        
        return MatchResult(blocked=False)
    
    def _match_rule(self, rule, request_data):
        """
        Applique une seule règle aux données de la requête.
        
        Args:
            rule: L'objet Rule à appliquer
            request_data: Dictionnaire contenant les données HTTP de la requête analysée
            
        Returns:
            MatchResult: Résultat de l'opération de correspondance de règle
        """
        for match_pattern in rule.match_patterns:
            if self._match_pattern(match_pattern, request_data):
                self.logger.info(f"Rule match: {rule.id} - {rule.name}")
                return MatchResult(
                    blocked='block' in rule.actions,
                    rule_id=rule.id,
                    reason=rule.description or rule.name,
                    actions=rule.actions
                )
        
        return MatchResult(blocked=False)
    
    def _match_pattern(self, match_pattern, request_data):
        """
        Correspond à un seul motif contre les données de la requête.
        
        Args:
            match_pattern: Dictionnaire contenant le motif et la cible
            request_data: Dictionnaire contenant les données HTTP de la requête analysée
            
        Returns:
            bool: True si le motif correspond, False sinon
        """
        if 'compiled_pattern' not in match_pattern or not match_pattern['compiled_pattern']:
            return False
        
        target = match_pattern.get('target', 'any')
        pattern = match_pattern['compiled_pattern']
        
        # Correspondance avec des parties spécifiques de la requête
        if target == 'url' or target == 'path':
            return bool(pattern.search(request_data['path']))
        
        elif target == 'query':
            # Correspondance avec n'importe quel paramètre de requête
            for param, value in request_data['query'].items():
                if pattern.search(param) or pattern.search(str(value)):
                    return True
        
        elif target == 'body':
            # Correspondance avec le contenu du corps
            if request_data['raw_body'] and pattern.search(str(request_data['raw_body'])):
                return True
            
            # Correspondance avec les paramètres du corps analysés
            for param, value in request_data['body'].items():
                if pattern.search(param) or pattern.search(str(value)):
                    return True
        
        elif target == 'header':
            # Correspondance avec n'importe quel en-tête
            for header, value in request_data['headers'].items():
                if pattern.search(header.lower()) or pattern.search(str(value)):
                    return True
        
        elif target == 'cookie':
            # Correspondance avec n'importe quel cookie
            for cookie, value in request_data['cookies'].items():
                if pattern.search(cookie) or pattern.search(str(value)):
                    return True
        
        elif target == 'any':
            # Essaye de faire correspondre avec toutes les parties de la requête
            # Chemin
            if pattern.search(request_data['path']):
                return True
            
            # Paramètres de requête
            for param, value in request_data['query'].items():
                if pattern.search(param) or pattern.search(str(value)):
                    return True
            
            # En-têtes
            for header, value in request_data['headers'].items():
                if pattern.search(header.lower()) or pattern.search(str(value)):
                    return True
            
            # Cookies
            for cookie, value in request_data['cookies'].items():
                if pattern.search(cookie) or pattern.search(str(value)):
                    return True
            
            # Contenu du corps
            if request_data['raw_body'] and pattern.search(str(request_data['raw_body'])):
                return True
            
            # Paramètres du corps
            for param, value in request_data['body'].items():
                if pattern.search(param) or pattern.search(str(value)):
                    return True
        
        return False