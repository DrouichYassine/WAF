"""
SQL Injection detection module.
"""

import re
import logging

class SQLInjectionDetector:
    """Detect SQL injection attacks in requests."""
    
    def __init__(self):
        """Initialize SQL injection detector with patterns."""
        self.logger = logging.getLogger('waf.modules.sqli')
        
        # SQL injection patterns
        self.patterns = [
            # Basic SQL injection
            re.compile(r"(?i)(\b(select|insert|update|delete|drop|alter|create|truncate)\b.*(from|table|into|values))", re.IGNORECASE),
            
            # Union-based SQL injection
            re.compile(r"(?i)(union\s+select)", re.IGNORECASE),
            
            # Boolean-based SQL injection
            re.compile(r"(?i)(\bor\b\s+\d+\s*=\s*\d+|\bor\b\s+\btrue\b|\bor\b\s+\b'\b\s*=\s*\b'\b)", re.IGNORECASE),
            
            # Error-based SQL injection
            re.compile(r"(?i)(convert\(.*using)|(cast\(.*as)|(@@version)", re.IGNORECASE),
            
            # Time-based SQL injection
            re.compile(r"(?i)(sleep\(\d+\)|waitfor\s+delay|pg_sleep)", re.IGNORECASE),
            
            # Special SQL characters/comments
            re.compile(r"(?i)(--\s+.*|\/\*.*\*\/|#.*$)", re.IGNORECASE)
        ]
    
    def detect(self, request_data):
        """
        Detect SQL injection in request data.
        
        Args:
            request_data: Dictionary containing parsed HTTP request data
            
        Returns:
            tuple: (is_detected, description)
        """
        # Check query parameters
        for param, value in request_data['query'].items():
            for pattern in self.patterns:
                if pattern.search(str(value)):
                    self.logger.warning(f"SQL injection detected in query param {param}: {value}")
                    return True, f"SQL injection in query parameter: {param}"
        
        # Check body parameters
        for param, value in request_data['body'].items():
            for pattern in self.patterns:
                if pattern.search(str(value)):
                    self.logger.warning(f"SQL injection detected in body param {param}: {value}")
                    return True, f"SQL injection in body parameter: {param}"
        
        # Check cookies
        for cookie, value in request_data['cookies'].items():
            for pattern in self.patterns:
                if pattern.search(str(value)):
                    self.logger.warning(f"SQL injection detected in cookie {cookie}: {value}")
                    return True, f"SQL injection in cookie: {cookie}"
        
        # Check URL path
        for pattern in self.patterns:
            if pattern.search(request_data['path']):
                self.logger.warning(f"SQL injection detected in path: {request_data['path']}")
                return True, "SQL injection in URL path"
        
        return False, None