class RegexDosScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        vulnerabilities = []
        
        # Test for ReDoS with problematic patterns
        test_payloads = [
            "a" * 1000 + "!",
            "a" * 10000 + "@example.com",
            "(" * 100 + ")" * 100
        ]
        
        for payload in test_payloads:
            start_time = time.time()
            response = requests.post(url, json={"value": payload}, 
                                  headers={"Authorization": f"Bearer {token}"} if token else {})
            response_time = time.time() - start_time
            
            if response_time > 5.0:  # Threshold for potential DoS
                vulnerabilities.append({
                    "type": "REGEX_DOS",
                    "severity": "HIGH",
                    "detail": "Potential ReDoS vulnerability detected",
                    "evidence": {
                        "url": url,
                        "method": method,
                        "payload": payload,
                        "response_time": response_time
                    }
                })
                
        return vulnerabilities