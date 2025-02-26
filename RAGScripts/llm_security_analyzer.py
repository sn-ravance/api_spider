import json
import ollama
import asyncio
from typing import Dict, Optional, List
from .utils.logger import setup_logger

class LLMSecurityAnalyzer:
    def __init__(self, model: str = "llama2"):
        self.model = model
        self.logger = setup_logger("llm_security_analyzer", verbosity=1)
        self.message_history = []  # Store chat history
        self.discovered_credentials = {}  # Store discovered credentials
        self.sensitive_info = {}  # Store other sensitive information

    async def analyze_request_response(self, 
        path: str,
        method: str,
        request_headers: Dict,
        request_body: Dict,
        response_headers: Dict,
        response_body: Dict,
        vulnerability_type: str
    ) -> Dict:
        """Analyze request/response pair for security vulnerabilities"""
        prompt = self._construct_security_prompt(
            path=path,
            method=method,
            request_headers=request_headers,
            request_body=request_body,
            response_headers=response_headers,
            response_body=response_body,
            vulnerability_type=vulnerability_type
        )
        
        try:
            analysis = await self._query_ollama(prompt)
            return await self._parse_security_analysis(analysis)
        except Exception as e:
            self.logger.error(f"Security analysis failed: {str(e)}")
            return {"error": str(e), "confidence": 0.0}

    def _construct_security_prompt(self,
        path: str,
        method: str,
        request_headers: Dict,
        request_body: Dict,
        response_headers: Dict,
        response_body: Dict,
        vulnerability_type: str
    ) -> str:
        """Construct prompt for security analysis"""
        return f"""Analyze this API interaction for {vulnerability_type} vulnerabilities:

Endpoint Information:
- Path: {path}
- Method: {method}

Request:
- Headers: {json.dumps(request_headers, indent=2)}
- Body: {json.dumps(request_body, indent=2)}

Response:
- Headers: {json.dumps(response_headers, indent=2)}
- Body: {json.dumps(response_body, indent=2)}

Provide a detailed security analysis focusing on:
1. Potential {vulnerability_type} vulnerabilities
2. Suspicious patterns in request/response
3. Security misconfigurations
4. Recommended security improvements

Format your response as JSON with:
- vulnerability_found (boolean)
- severity (string: low/medium/high/critical)
- confidence_score (float: 0-1)
- findings (array of strings)
- recommendations (array of strings)
"""

    async def _query_ollama(self, prompt: str) -> str:
        """Query Ollama with retry mechanism and maintain chat history"""
        max_retries = 3
        
        # Add context from previous findings if available
        context_prompt = self._build_context_prompt()
        if context_prompt:
            prompt = context_prompt + "\n\n" + prompt
        
        # Add the new prompt to message history
        self.message_history.append({"role": "user", "content": prompt})
        
        for attempt in range(max_retries):
            try:
                response = await asyncio.to_thread(
                    ollama.chat,
                    model=self.model,
                    messages=self.message_history
                )
                
                # Store the response in history
                self.message_history.append({"role": "assistant", "content": response['message']['content']})
                
                # Update discovered information
                self._update_discovered_info(response['message']['content'])
                
                return response['message']['content']
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(1 * (attempt + 1))

    async def _parse_security_analysis(self, response: str) -> Dict:
        """Parse and validate security analysis response"""
        try:
            # Try direct JSON parsing
            result = json.loads(response)
        except json.JSONDecodeError:
            # Fallback to extracting JSON from text
            try:
                json_str = response[response.find('{'):response.rfind('}')+1]
                result = json.loads(json_str)
            except (json.JSONDecodeError, ValueError):
                # Structured fallback response
                result = self._create_fallback_analysis(response)

        # Validate and normalize result
        return self._normalize_analysis_result(result)

    def _create_fallback_analysis(self, response: str) -> Dict:
        """Create structured analysis from non-JSON response"""
        lines = response.split('\n')
        findings = []
        recommendations = []

        for line in lines:
            line = line.strip()
            if line.startswith('- '):
                if 'recommend' in line.lower():
                    recommendations.append(line[2:])
                else:
                    findings.append(line[2:])

        return {
            "vulnerability_found": len(findings) > 0,
            "severity": "medium" if findings else "low",
            "confidence_score": 0.5,
            "findings": findings,
            "recommendations": recommendations
        }

    def _normalize_analysis_result(self, result: Dict) -> Dict:
        """Normalize and validate analysis result"""
        return {
            "vulnerability_found": bool(result.get("vulnerability_found", False)),
            "severity": str(result.get("severity", "low")).lower(),
            "confidence_score": float(result.get("confidence_score", 0.5)),
            "findings": list(result.get("findings", [])),
            "recommendations": list(result.get("recommendations", [])),
            "context": {
                "discovered_credentials": self.discovered_credentials,
                "sensitive_info": self.sensitive_info
            }
        }

    def _build_context_prompt(self) -> str:
        """Build context prompt from discovered information"""
        if not self.discovered_credentials and not self.sensitive_info:
            return ""

        context = ["Previous scan findings:"]
        
        if self.discovered_credentials:
            context.append("\nDiscovered credentials:")
            for endpoint, creds in self.discovered_credentials.items():
                context.append(f"- {endpoint}: {json.dumps(creds)}")
        
        if self.sensitive_info:
            context.append("\nOther sensitive information:")
            for info_type, details in self.sensitive_info.items():
                context.append(f"- {info_type}: {json.dumps(details)}")
        
        return "\n".join(context)

    def _update_discovered_info(self, response: str) -> None:
        """Update discovered credentials and sensitive information from response"""
        try:
            result = json.loads(response)
            findings = result.get("findings", [])
            
            for finding in findings:
                # Look for credentials in findings
                if any(kw in finding.lower() for kw in ["password", "credential", "token", "api key"]):
                    self.discovered_credentials[result.get("endpoint", "unknown")] = finding
                
                # Look for other sensitive information
                if any(kw in finding.lower() for kw in ["pii", "sensitive", "personal", "private"]):
                    info_type = "pii" if "pii" in finding.lower() else "sensitive_data"
                    self.sensitive_info[info_type] = finding
        except:
            pass