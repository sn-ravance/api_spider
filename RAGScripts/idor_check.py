from .base_scanner import BaseScanner
from typing import List, Dict, Any

class IDORScanner(BaseScanner):
    async def scan(self, url: str, method: str, **kwargs) -> List[Dict[str, Any]]:
        # IDOR scanning implementation
        findings = []
        
        # Test for IDOR by accessing objects with different auth contexts
        test_cases = [
            {"id": "123", "auth": None},
            {"id": "123", "auth": token},
            {"id": "123", "auth": "different_user_token"}
        ]
        
        for case in test_cases:
            headers = {"Authorization": f"Bearer {case['auth']}"} if case['auth'] else {}
            response = requests.get(f"{url}/{case['id']}", headers=headers)
            
            if IDORScanner._is_idor_vulnerable(response, case):
                vulnerabilities.append({
                    "type": "IDOR",
                    "severity": "HIGH",
                    "detail": "Direct object reference possible with different auth context",
                    "evidence": {
                        "url": url,
                        "method": method,
                        "test_case": case,
                        "response": response.text[:500]
                    }
                })
                
        return vulnerabilities