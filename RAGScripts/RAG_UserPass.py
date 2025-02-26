#!/usr/bin/env python3
"""
User & Password Enumeration Test Script
Checks if an API endpoint is vulnerable to user enumeration by analyzing
differences in error messages between valid and invalid usernames.
"""

import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class UserPassEnumScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict]:
        logger = setup_scanner_logger("user_pass_enum")
        vulnerabilities = []
        
        # Test usernames
        usernames = ["admin", "testuser", "nonexistentuser"]
        password = "wrongpassword"
        login_url = f"{url}/users/v1/login"
        
        if headers is None:
            headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        try:
            for username in usernames:
                payload = {
                    "username": username,
                    "password": password
                }
                
                response = requests.post(
                    login_url,
                    json=payload,
                    timeout=5
                )
                
                # Analyze response for user enumeration
                if response.status_code == 200:
                    response_text = response.text.lower()
                    if ("incorrect" in response_text or 
                        "invalid password" in response_text or
                        "password is not correct" in response_text):
                        vulnerabilities.append({
                            "type": "USER_ENUMERATION",
                            "severity": "MEDIUM",
                            "detail": f"Different error message for existing username: {username}",
                            "evidence": {
                                "url": login_url,
                                "username": username,
                                "response": response.text
                            }
                        })
                        
        except requests.RequestException as e:
            logger.error(f"Error in user enumeration check: {str(e)}")
            
        return vulnerabilities

scan = UserPassEnumScanner.scan
