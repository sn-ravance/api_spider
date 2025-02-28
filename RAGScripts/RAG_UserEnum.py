#!/usr/bin/env python3
"""User Enumeration Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class UserEnumScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("user_enum")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        test_users = ["admin", "root", "administrator", "superuser"]
        base_response = None
        
        try:
            # Get base response for comparison
            base_resp = self.make_request(
                method=method,
                endpoint=path,
                data={"username": "nonexistent_user_" + str(int(self.time.time()))}
            )
            base_response = base_resp.text
            
            for username in test_users:
                test_resp = self.make_request(
                    method=method,
                    endpoint=path,
                    data={"username": username}
                )
                
                if test_resp.text != base_response:
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="User Enumeration Vulnerability",
                        description=f"Different error message for existing username: {username}",
                        endpoint=path,
                        severity_level="tier1",
                        impact="Information disclosure enabling user enumeration",
                        request=request_data,
                        response=response_data,
                        remediation="Use consistent error messages for all authentication attempts"
                    )
                    
        except requests.RequestException as e:
            self.logger.error(f"Error in user enumeration check: {str(e)}")
            
        return self.findings

scan = UserEnumScanner().scan