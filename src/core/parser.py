# Analyseur de requêtes/réponses HTTP.

import urllib.parse
import json
import logging

class HTTPParser:
    # Analyseur pour les requêtes et réponses HTTP.
    
    def __init__(self, headers, path, method, body=None):
        # Initialiser avec les données de la requête HTTP.
        self.headers = headers
        self.path = path
        self.method = method
        self.body = body
        self.logger = logging.getLogger('waf.parser')
    
    def parse_request(self):
        # Analyser la requête HTTP en données structurées pour le traitement des règles.
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        
        # Analyser les paramètres de requête
        query_params = {}
        if parsed_url.query:
            query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
        
        # Analyser les cookies
        cookies = {}
        cookie_header = self.headers.get('Cookie', '')
        if cookie_header:
            cookie_parts = cookie_header.split('; ')
            for part in cookie_parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    cookies[key] = value
        
        # Analyser les données du corps
        body_data = {}
        content_type = self.headers.get('Content-Type', '')
        
        if self.body:
            if 'application/x-www-form-urlencoded' in content_type:
                try:
                    body_data = dict(urllib.parse.parse_qsl(self.body.decode('utf-8')))
                except Exception as e:
                    self.logger.warning(f"Failed to parse form data: {e}")
            
            elif 'application/json' in content_type:
                try:
                    body_data = json.loads(self.body.decode('utf-8'))
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse JSON data: {e}")
        
        # Créer des données de requête structurées
        request_data = {
            'method': self.method,
            'path': path,
            'query': query_params,
            'headers': dict(self.headers.items()),
            'cookies': cookies,
            'body': body_data,
            'raw_body': self.body,
            'client_ip': self.headers.get('X-Forwarded-For', '').split(',')[0].strip() or '127.0.0.1',
            'user_agent': self.headers.get('User-Agent', '')
        }
        
        return request_data