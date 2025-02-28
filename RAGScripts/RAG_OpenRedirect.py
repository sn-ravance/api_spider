#!/usr/bin/env python3
"""Open Redirect Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class OpenRedirectScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("open_redirect")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "\\\\evil.com",
            "evil.com/%2F..",
            "https:evil.com",
            "https://evil.com%23.target.com",
            "https://target.com@evil.com"
        ]
        
        for payload in redirect_payloads:
            try:
                test_resp = self.make_request(
                    method=method,
                    endpoint=f"{path}?redirect={payload}&url={payload}&next={payload}",
                    headers={"Content-Type": "application/json"},
                    allow_redirects=False
                )
                
                if test_resp.status_code in [301, 302, 303, 307, 308]:
                    location = test_resp.headers.get('Location', '')
                    if any(p.replace('evil.com', '') in location.lower() for p in redirect_payloads):
                        request_data, response_data = self.capture_transaction(test_resp)
                        
                        self.add_finding(
                            title="Open Redirect Vulnerability",
                            description=f"Endpoint allows redirect to arbitrary URL: {payload}",
                            endpoint=path,
                            severity_level="tier1",
                            impact="Phishing attacks and credential theft through malicious redirects",
                            request=request_data,
                            response=response_data,
                            remediation="Implement strict URL validation and use allowlist for redirect destinations"
                        )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing redirect payload {payload}: {str(e)}")
                
        return self.findings

scan = OpenRedirectScanner().scan