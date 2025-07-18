"""
Core WAF engine module responsible for processing HTTP traffic
and applying security rules.
"""

import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from src.rules.rule_loader import RuleLoader
from src.rules.matcher import RuleMatcher
from src.core.parser import HTTPParser

class WAFProxy(BaseHTTPRequestHandler):
    """Proxy handler for intercepting and processing HTTP requests."""
    
    def __init__(self, *args, **kwargs):
        self.rule_matcher = kwargs.pop('rule_matcher')
        self.logger = kwargs.pop('logger')
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests."""
        self._process_request('GET')
    
    def do_POST(self):
        """Handle POST requests."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else None
        self._process_request('POST', post_data)
        
    def _process_request(self, method, post_data=None):
        """Process incoming HTTP request."""
        try:
            # Parse the request
            parser = HTTPParser(self.headers, self.path, method, post_data)
            request_data = parser.parse_request()
            
            # Apply WAF rules
            result = self.rule_matcher.match_request(request_data)
            
            if result.blocked:
                self.logger.warning(f"Blocked request: {result.reason}")
                self._send_forbidden(result.reason)
            else:
                # Forward request to backend
                self._forward_request(request_data)
        
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            self._send_error()
    
    def _send_forbidden(self, reason):
        """Send 403 Forbidden response."""
        self.send_response(403)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        response = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f8f8f8;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }}
            .error-container {{
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                padding: 30px;
                max-width: 600px;
                text-align: center;
            }}
            h1 {{
                color: #e74c3c;
                margin-bottom: 20px;
            }}
            p {{
                color: #555;
                margin-bottom: 20px;
            }}
            .icon {{
                font-size: 60px;
                margin-bottom: 20px;
                color: #e74c3c;
            }}
        </style>
    </head>
    <body>
        <div class="error-container">
            <h1>Access denied</h1>
            <p>Your request has been blocked by our security system.</p>
            <p>Reason: {reason}</p>
        </div>
    </body>
    </html>
    """
        self.wfile.write(response.encode())
    
    def _send_error(self):
        """Send 500 error response."""
        self.send_response(500)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        response = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f8f8f8;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }}
            .error-container {{
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                padding: 30px;
                max-width: 600px;
                text-align: center;
            }}
            h1 {{
                color: #e74c3c;
                margin-bottom: 20px;
            }}
            p {{
                color: #555;
                margin-bottom: 20px;
            }}
            .icon {{
                font-size: 60px;
                margin-bottom: 20px;
                color: #e74c3c;
            }}
        </style>
    </head>
    <body>
        <div class="error-container">
            <h1>500 Internal Server Error</h1>
            <p>Your request has encountered an unexpected error.</p>
            <p>Reason: {reason}</p>
        </div>
    </body>
    </html>
    """
    
    # Convertir la chaîne formatée en bytes pour l'écriture
        self.wfile.write(response.encode())
    
    def _forward_request(self, request_data):
        """Forward request to backend server."""
        # This is a simplified version. In a real implementation,
        # we would forward the request to the backend server
        # and relay the response back to the client.
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        response = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f8f8f8;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }}
            .error-container {{
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                padding: 30px;
                max-width: 600px;
                text-align: center;
            }}
            h1 {{
                color: #e74c3c;
                margin-bottom: 20px;
            }}
            p {{
                color: #555;
                margin-bottom: 20px;
            }}
            .icon {{
                font-size: 60px;
                margin-bottom: 20px;
                color: #e74c3c;
            }}
        </style>
    </head>
    <body>
        <div class="error-container">
            <h1>Request Passed</h1>
            <p>Your request has passed all WAF checks.</p>
        </div>
    </body>
    </html>
    """
    
    # Convertir la chaîne formatée en bytes pour l'écriture
        self.wfile.write(response.encode())


class WAFEngine:
    """Core WAF engine class."""
    
    def __init__(self, config):
        """Initialize WAF engine with configuration."""
        self.config = config
        self.logger = logging.getLogger('waf')
        self.rule_loader = RuleLoader(config['rules_path'])
        self.rules = self.rule_loader.load_rules()
        self.rule_matcher = RuleMatcher(self.rules)
        
    def start(self):
        """Start the WAF server."""
        host = self.config.get('listen_host', '127.0.0.1')
        port = int(self.config.get('listen_port', 8080))
        
        def handler(*args):
            WAFProxy(*args, rule_matcher=self.rule_matcher, logger=self.logger)
        
        server = HTTPServer((host, port), handler)
        self.logger.info(f"Starting WAF on {host}:{port}")
        
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        
        server.server_close()
        self.logger.info("WAF stopped")