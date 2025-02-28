#!/usr/bin/env python3
"""CORS Misconfiguration Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class CORSScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("cors")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        test_origins = [
            "https://evil.com",
            "http://attacker.com",
            "null",
            "*",
            f"https://{url}.evil.com",
            "https://evil.{url}",
            "file://"
        ]
        
        for origin in test_origins:
            try:
                test_headers = {
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization"
                }
                
                test_resp = self.make_request(
                    method="OPTIONS",
                    endpoint=path,
                    headers=test_headers
                )
                
                acao = test_resp.headers.get("Access-Control-Allow-Origin")
                if acao and (acao == "*" or origin in acao):
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="CORS Misconfiguration",
                        description=f"Endpoint allows CORS from dangerous origin: {origin}",
                        endpoint=path,
                        severity_level="tier2",
                        impact="Cross-origin resource sharing enables malicious sites to access sensitive data",
                        request=request_data,
                        response=response_data,
                        remediation="Implement strict CORS policy with specific allowed origins"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing CORS origin {origin}: {str(e)}")
                
        return self.findings

scan = CORSScanner().scan