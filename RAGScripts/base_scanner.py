
#!/usr/bin/env python3

import json
import sys
import argparse
import logging
import requests
from typing import Dict, List, Optional, Union
from datetime import datetime
import uuid
from urllib.parse import urljoin
import time
from abc import ABC, abstractmethod
from .utils.logger import setup_logger
from typing import List, Dict, Any
from .llm_analyzer import LLMAnalyzer

class BaseScanner(ABC):
    def __init__(self):
        self.logger = setup_logger(self.__class__.__name__)
        self.findings = []
        self.session = requests.Session()
        self.llm_analyzer = LLMAnalyzer()

    @abstractmethod
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Base scan method to be implemented by child classes
        
        Args:
            url (str): Target URL to scan
            method (str): HTTP method to use
            path (str): API endpoint path
            response (requests.Response): Initial response from the endpoint
            token (str, optional): Authentication token
            headers (Dict[str, str], optional): Request headers
            
        Returns:
            List[Dict[str, Any]]: List of discovered vulnerabilities
        """
        raise NotImplementedError("Scan method must be implemented by child classes")

    def validate_finding(self, finding: Dict) -> bool:
        """Basic validation of finding format"""
        required_fields = ['type', 'severity', 'detail', 'evidence']
        return all(field in finding for field in required_fields)

    def validate_response(self, response) -> bool:
        """Basic response validation"""
        return True

    def setup_logging(self) -> None:
        """Configure structured logging for the scanner."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(self.__class__.__name__)

    def setup_arguments(self):
        """Set up command line arguments"""
        parser = argparse.ArgumentParser()
        parser.add_argument('--target', required=True, help='Target API URL')
        parser.add_argument('--auth', help='Authentication token or JSON credentials')
        self.args = parser.parse_args()
        
        # Handle auth argument
        if self.args.auth:
            try:
                # First try to parse as JSON
                self.auth = json.loads(self.args.auth)
            except json.JSONDecodeError:
                # If not JSON, treat as raw token
                self.auth = {"Authorization": f"Bearer {self.args.auth}"}
        else:
            self.auth = None
        self.target = self.args.target.rstrip('/')

    def configure_auth(self) -> None:
        """Configure authentication based on provided credentials."""
        auth_type = self.auth.get('type', 'none')
        credentials = self.auth.get('credentials', {})

        if auth_type == 'basic':
            self.session.auth = (
                credentials.get('username', ''),
                credentials.get('password', '')
            )
        elif auth_type == 'bearer':
            self.session.headers['Authorization'] = f"Bearer {credentials.get('token', '')}"
        elif auth_type == 'apikey':
            header_name = credentials.get('headerName', 'X-API-Key')
            self.session.headers[header_name] = credentials.get('apiKey', '')

    def make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Union[Dict, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        verify: bool = True,
        allow_redirects: bool = True
    ) -> requests.Response:
        """
        Make an HTTP request with full transaction capture.
        """
        url = urljoin(self.target, endpoint)
        request_headers = {**self.session.headers}
        if headers:
            request_headers.update(headers)

        start_time = time.time()
        self.logger.info(f"Making {method} request to {url}")

        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=request_headers,
                data=json.dumps(data) if isinstance(data, dict) else data,
                params=params,
                timeout=timeout,
                verify=verify,
                allow_redirects=allow_redirects
            )
            elapsed = time.time() - start_time
            self.logger.info(f"Request completed in {elapsed:.2f}s with status {response.status_code}")
            return response

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {str(e)}")
            raise

    def capture_transaction(
        self,
        response: requests.Response
    ) -> tuple[Dict, Dict]:
        """
        Capture full HTTP transaction details from a response object.
        """
        # Capture request details
        request_data = {
            "method": response.request.method,
            "url": response.request.url,
            "headers": dict(response.request.headers),
            "body": response.request.body or ""
        }

        # Capture response details
        response_data = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "elapsed": response.elapsed.total_seconds()
        }

        return request_data, response_data

    def add_finding(
        self,
        title: str,
        description: str,
        endpoint: str,
        severity_level: str,
        impact: str,
        request: Dict,
        response: Dict,
        remediation: str
    ) -> None:
        """
        Add a security finding with full transaction details.
        """
        finding = {
            "id": str(uuid.uuid4()),
            "title": title,
            "description": description,
            "endpoint": endpoint,
            "severity": {
                "level": severity_level,
                "description": self.get_severity_description(severity_level)
            },
            "impact": impact,
            "request": request,
            "response": response,
            "remediation": remediation,
            "timestamp": datetime.utcnow().isoformat(),
            "scanner": self.__class__.__name__
        }
        
        # Analyze finding with LLM for additional context and insights
        llm_analysis = self.llm_analyzer.analyze_finding(finding)
        if llm_analysis:
            finding["llm_analysis"] = llm_analysis
        
        self.logger.info(f"Adding finding: {title} ({severity_level})")
        self.findings.append(finding)

    def get_severity_description(self, level: str) -> str:
        """Get the description for a severity level."""
        descriptions = {
            "bot": "Bot - Automated attacks, Low complexity, High volume",
            "script": "Script Kiddie - Basic exploitation, Known vulnerabilities, Common tools",
            "tier1": "Tier 1 Validator - Intermediate threats, Some customization, Basic chaining",
            "tier2": "Tier 2 Hacker - Advanced attacks, Custom exploits, Complex chains",
            "tier3": "Tier 3 Elite - Sophisticated exploits, Zero-days, Advanced persistence"
        }
        return descriptions.get(level, "Unknown severity level")

    def run(self) -> None:
        """
        Main execution method to be implemented by scanner subclasses.
        """
        raise NotImplementedError("Subclasses must implement run()")

    def execute(self) -> None:
        """
        Execute the scanner with proper error handling and output formatting.
        """
        start_time = time.time()
        self.logger.info(f"Starting scan of {self.target}")

        try:
            self.run()
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}", exc_info=True)
            self.add_finding(
                "Scanner Error",
                f"Error during scan execution: {str(e)}",
                self.target,
                "bot",
                "Scanner failed to complete execution",
                {"error": str(e)},
                {"error": "Scan failed"},
                "Check scanner logs and fix implementation issues"
            )
        finally:
            elapsed = time.time() - start_time
            self.logger.info(f"Scan completed in {elapsed:.2f}s with {len(self.findings)} findings")
            print(json.dumps(self.findings))

if __name__ == "__main__":
    print("This is a base scanner class and should not be run directly")
    sys.exit(1)
