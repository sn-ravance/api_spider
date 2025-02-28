#!/usr/bin/env python3
"""Cross-Site Scripting (XSS) Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class XSSScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("xss")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        xss_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>"
        ]
        
        for payload in xss_payloads:
            try:
                test_resp = self.make_request(
                    method=method,
                    endpoint=path,
                    data={"input": payload},
                    headers={"Content-Type": "application/json"}
                )
                
                if payload in test_resp.text:
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="Cross-Site Scripting (XSS) Vulnerability",
                        description=f"XSS payload reflected in response: {payload}",
                        endpoint=path,
                        severity_level="tier2",
                        impact="Client-side code execution and session hijacking",
                        request=request_data,
                        response=response_data,
                        remediation="Implement proper input validation and output encoding"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing XSS payload {payload}: {str(e)}")
                
        return self.findings

scan = XSSScanner().scan