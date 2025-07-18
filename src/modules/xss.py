"""
Cross-Site Scripting (XSS) detection module.
"""

import re
import logging
import html

class XSSDetector:
    """Detect XSS attacks in requests."""
    
    def __init__(self):
        """Initialize XSS detector with patterns."""
        self.logger = logging.getLogger('waf.modules.xss')
        
        # XSS patterns
        self.patterns = [
            # Script tags
            re.compile(r"(?i)<script.*?>.*?</script.*?>", re.IGNORECASE | re.DOTALL),
            re.compile(r"(?i)<script.*?>"),
            
            # Event handlers
            re.compile(r"(?i)\bon\w+\s*=", re.IGNORECASE),
            
            # JavaScript protocol
            re.compile(r"(?i)javascript:", re.IGNORECASE),
            
            # Inline expressions
            re.compile(r"(?i)expression\s*\(", re.IGNORECASE),
            
            # Eval and similar functions
            re.compile(r"(?i)\b(eval|setTimeout|setInterval|Function|execScript)\s*\(", re.IGNORECASE),
            
            # Data URIs
            re.compile(r"(?i)data:text/html", re.IGNORECASE),
            
            # SVG script content
            re.compile(r"(?i)<svg.*?>.*?<script.*?>.*?</script.*?>.*?</svg.*?>", re.IGNORECASE | re.DOTALL),
            
            # Common attack vectors
            re.compile(r"(?i)<img.*?onerror=.*?>", re.IGNORECASE),
            re.compile(r"(?i)<iframe.*?>", re.IGNORECASE),
            re.compile(r"(?i)<object.*?>", re.IGNORECASE)
        ]
    
    def detect(self, request_data):
        """
        Detect XSS in request data.
        
        Args:
            request_data: Dictionary containing parsed HTTP request data
            
        Returns:
            tuple: (is_detected, description)
        """
        # Check query parameters
        for param, value in request_data['query'].items():
            for pattern in self.patterns:
                if pattern.search(str(value)):
                    self.logger.warning(f"XSS detected in query param {param}: {value}")
                    return True, f"XSS in query parameter: {param}"
        
        # Check body parameters
        for param, value in request_data['body'].items():
            for pattern in self.patterns:
                if pattern.search(str(value)):
                    self.logger.warning(f"XSS detected in body param {param}: {value}")
                    return True, f"XSS in body parameter: {param}"
        
        # Check cookies
        for cookie, value in request_data['cookies'].items():
            for pattern in self.patterns:
                if pattern.search(str(value)):
                    self.logger.warning(f"XSS detected in cookie {cookie}: {value}")
                    return True, f"XSS in cookie: {cookie}"
        
        # Check URL path
        for pattern in self.patterns:
            if pattern.search(request_data['path']):
                self.logger.warning(f"XSS detected in path: {request_data['path']}")
                return True, "XSS in URL path"
        
        return False, None
    
    def sanitize(self, input_string):
        """
        Sanitize a string to prevent XSS.
        
        Args:
            input_string: String to sanitize
            
        Returns:
            str: Sanitized string
        """
        if not isinstance(input_string, str):
            return input_string
        
        # HTML escape the string
        sanitized = html.escape(input_string)
        
        # Remove JavaScript event handlers
        sanitized = re.sub(r"(?i)\bon\w+\s*=", "", sanitized)
        
        # Remove JavaScript protocol
        sanitized = re.sub(r"(?i)javascript:", "blocked:", sanitized)
        
        return sanitized