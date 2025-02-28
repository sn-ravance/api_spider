#!/usr/bin/env python3
"""Command Injection Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class CommandInjectionScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("cmdi")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        cmdi_payloads = [
            "; ls",
            "| ls",
            "`ls`",
            "$(ls)",
            "; sleep 5",
            "| sleep 5",
            "`sleep 5`",
            "$(sleep 5)"
        ]
        
        for payload in cmdi_payloads:
            try:
                start_time = self.time.time()
                test_resp = self.make_request(
                    method=method,
                    endpoint=path,
                    data={"command": payload},
                    headers={"Content-Type": "application/json"}
                )
                execution_time = self.time.time() - start_time
                
                if execution_time > 4 or "bin" in test_resp.text:
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="Command Injection Vulnerability",
                        description=f"Potential command injection detected with payload: {payload}",
                        endpoint=path,
                        severity_level="tier3",
                        impact="Remote code execution and system compromise",
                        request=request_data,
                        response=response_data,
                        remediation="Avoid shell commands, use APIs or libraries, implement strict input validation"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing command injection payload {payload}: {str(e)}")
                
        return self.findings

scan = CommandInjectionScanner().scan