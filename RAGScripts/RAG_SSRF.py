#!/usr/bin/env python3
"""Server-Side Request Forgery Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class SSRFScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("ssrf")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        ssrf_payloads = [
            "http://localhost:22",
            "http://127.0.0.1:22",
            "http://[::]:22",
            "http://169.254.169.254/latest/meta-data/",
            "http://instance-data/latest/meta-data/",
            "file:///etc/passwd",
            "dict://localhost:11211/"
        ]
        
        for payload in ssrf_payloads:
            try:
                test_resp = self.make_request(
                    method=method,
                    endpoint=path,
                    data={"url": payload, "endpoint": payload},
                    headers={"Content-Type": "application/json"}
                )
                
                if test_resp.status_code != 404 and len(test_resp.text) > 0:
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="Server-Side Request Forgery",
                        description=f"Potential SSRF detected with payload: {payload}",
                        endpoint=path,
                        severity_level="tier2",
                        impact="Internal network access and potential cloud metadata exposure",
                        request=request_data,
                        response=response_data,
                        remediation="Implement URL validation, whitelist allowed domains, and block internal addresses"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing SSRF payload {payload}: {str(e)}")
                
        return self.findings

scan = SSRFScanner().scan