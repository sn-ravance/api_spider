#!/usr/bin/env python3
"""Host Header Injection Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class HostHeaderScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("host_header")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        malicious_hosts = [
            "evil.com",
            "localhost",
            "127.0.0.1",
            "internal-service",
            "169.254.169.254",
            f"{url}@evil.com",
            f"{url}.evil.com"
        ]
        
        for host in malicious_hosts:
            try:
                test_headers = {
                    "Host": host,
                    "X-Forwarded-Host": host,
                    "X-Host": host,
                    "X-Forwarded-Server": host,
                    "Content-Type": "application/json"
                }
                
                test_resp = self.make_request(
                    method=method,
                    endpoint=path,
                    headers=test_headers
                )
                
                if host in test_resp.text or test_resp.status_code in [301, 302]:
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="Host Header Injection",
                        description=f"Endpoint is vulnerable to Host header manipulation: {host}",
                        endpoint=path,
                        severity_level="tier2",
                        impact="Cache poisoning and request routing manipulation",
                        request=request_data,
                        response=response_data,
                        remediation="Validate Host header and implement proper header validation"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing Host header {host}: {str(e)}")
                
        return self.findings

scan = HostHeaderScanner().scan