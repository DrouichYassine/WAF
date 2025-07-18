"""
Rule matcher module for applying WAF rules to HTTP requests.
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class MatchResult:
    """Result of a rule matching operation."""
    blocked: bool = False
    rule_id: Optional[str] = None
    reason: Optional[str] = None
    actions: List[str] = None

class RuleMatcher:
    """Apply WAF rules to HTTP requests."""
    
    def __init__(self, rules):
        """Initialize with a list of WAF rules."""
        self.rules = rules
        self.logger = logging.getLogger('waf.matcher')
    
    def match_request(self, request_data):
        """
        Apply all rules to the request and return the result.
        
        Args:
            request_data: Dictionary containing parsed HTTP request data
            
        Returns:
            MatchResult: Result of rule matching operation
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
        Apply a single rule to the request data.
        
        Args:
            rule: The Rule object to apply
            request_data: Dictionary containing parsed HTTP request data
            
        Returns:
            MatchResult: Result of rule matching operation
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
        Match a single pattern against the request data.
        
        Args:
            match_pattern: Dictionary containing pattern and target
            request_data: Dictionary containing parsed HTTP request data
            
        Returns:
            bool: True if pattern matches, False otherwise
        """
        if 'compiled_pattern' not in match_pattern or not match_pattern['compiled_pattern']:
            return False
        
        target = match_pattern.get('target', 'any')
        pattern = match_pattern['compiled_pattern']
        
        # Match against specific parts of the request
        if target == 'url' or target == 'path':
            return bool(pattern.search(request_data['path']))
        
        elif target == 'query':
            # Match against any query parameter
            for param, value in request_data['query'].items():
                if pattern.search(param) or pattern.search(str(value)):
                    return True
        
        elif target == 'body':
            # Match against body content
            if request_data['raw_body'] and pattern.search(str(request_data['raw_body'])):
                return True
            
            # Match against parsed body parameters
            for param, value in request_data['body'].items():
                if pattern.search(param) or pattern.search(str(value)):
                    return True
        
        elif target == 'header':
            # Match against any header
            for header, value in request_data['headers'].items():
                if pattern.search(header.lower()) or pattern.search(str(value)):
                    return True
        
        elif target == 'cookie':
            # Match against any cookie
            for cookie, value in request_data['cookies'].items():
                if pattern.search(cookie) or pattern.search(str(value)):
                    return True
        
        elif target == 'any':
            # Try to match against all parts of the request
            # Path
            if pattern.search(request_data['path']):
                return True
            
            # Query parameters
            for param, value in request_data['query'].items():
                if pattern.search(param) or pattern.search(str(value)):
                    return True
            
            # Headers
            for header, value in request_data['headers'].items():
                if pattern.search(header.lower()) or pattern.search(str(value)):
                    return True
            
            # Cookies
            for cookie, value in request_data['cookies'].items():
                if pattern.search(cookie) or pattern.search(str(value)):
                    return True
            
            # Body content
            if request_data['raw_body'] and pattern.search(str(request_data['raw_body'])):
                return True
            
            # Body parameters
            for param, value in request_data['body'].items():
                if pattern.search(param) or pattern.search(str(value)):
                    return True
        
        return False