import json
import httpx
import asyncio
import ollama
from typing import Dict, Any, Optional, List
from .utils.logger import setup_logger
from .utils.prompt_templates import (
    SECURITY_ANALYSIS_TEMPLATE,
    BEHAVIOR_ANALYSIS_TEMPLATE,
    METHOD_ANALYSIS_TEMPLATE
)

class LLMAnalyzer:
    def __init__(self, openai_key: Optional[str] = None, ollama_host: str = "http://localhost:11434"):
        self.openai_key = openai_key
        self.ollama_host = ollama_host
        self.ollama_model = "llama3.3"
        self.logger = setup_logger("llm_analyzer", verbosity=1)
        self.ollama_client = ollama.AsyncClient(host=ollama_host)
        
    async def analyze_endpoint(self, url: str, context: Dict, prompt: str) -> Dict:
        """Enhanced endpoint analysis with retries and fallback"""
        try:
            # Primary analysis
            response = await self._query_llm(prompt.format(
                url=url,
                **context
            ))
            
            result = await self._parse_analysis_response(response)
            
            # If confidence is low, perform secondary analysis
            if result.get('confidence', 1.0) < 0.7:
                secondary_response = await self._query_llm(
                    f"Review and validate this analysis:\n{json.dumps(result, indent=2)}\n"
                    f"For endpoint: {url}\n"
                    "Provide corrections or confirmations."
                )
                
                secondary_result = await self._parse_analysis_response(secondary_response)
                result.update(secondary_result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            return {"error": str(e), "confidence": 0.0}

    async def _query_llm(self, prompt: str) -> str:
        """Query LLM with improved error handling"""
        try:
            if self.openai_key:
                return await self._query_openai(prompt)
            return await self._query_ollama(prompt)
        except Exception as e:
            self.logger.error(f"LLM query failed: {str(e)}")
            raise

    async def _query_ollama(self, prompt: str) -> str:
        """Query Ollama using the official Python client"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = await self.ollama_client.generate(
                    model=self.ollama_model,
                    prompt=prompt,
                    stream=False
                )
                return response.response
            except ollama.ResponseError as e:
                if attempt == max_retries - 1:
                    return json.dumps({
                        "analysis": "LLM analysis unavailable - Ollama error",
                        "confidence": 0.0,
                        "recommendations": [f"Error: {str(e)}"],
                        "error": str(e)
                    })
                await asyncio.sleep(1 * (attempt + 1))
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(1 * (attempt + 1))
        return json.dumps({"error": "Max retries exceeded", "confidence": 0.0})

    async def _query_openai(self, prompt: str) -> str:
        """Query OpenAI with enhanced error handling"""
        # Create a new client for each request
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.openai_key}"},
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.7
                }
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]

    async def _parse_analysis_response(self, response: str) -> Dict:
        """Enhanced response parsing with fallback mechanisms"""
        try:
            # Try direct JSON parsing
            return json.loads(response)
        except json.JSONDecodeError:
            try:
                # Try extracting JSON from text
                json_str = response[response.find('{'):response.rfind('}')+1]
                return json.loads(json_str)
            except (json.JSONDecodeError, ValueError):
                # Fallback to structured text parsing
                return self._parse_text_response(response)

    def _parse_text_response(self, response: str) -> Dict:
        """Parse non-JSON response into structured format"""
        result = {
            "confidence": 0.5,
            "findings": [],
            "recommendations": []
        }
        
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if line.endswith(':'):
                current_section = line[:-1].lower()
            elif current_section:
                if current_section == 'findings':
                    result['findings'].append(line)
                elif current_section == 'recommendations':
                    result['recommendations'].append(line)
                    
        return result

    async def analyze_vulnerability(self, scanner_name: str, finding: Dict, url: str, method: str) -> Dict:
        """Analyze potential vulnerability with context"""
        prompt = f"""Analyze this security finding:
Scanner: {scanner_name}
Method: {method}
URL: {url}
Finding: {json.dumps(finding, indent=2)}

Determine if this is a genuine security issue or false positive.
Provide reasoning and confidence score.
"""
        response = await self._query_llm(prompt)
        return await self._parse_analysis_response(response)

    async def get_ollama_models(self) -> List[str]:
        """Get list of available Ollama models using the official client"""
        try:
            models = await self.ollama_client.list()
            return [model['name'] for model in models['models']]
        except Exception as e:
            self.logger.error(f"Error fetching Ollama models: {e}")
            return []

    async def get_openai_models(self, api_key: str) -> List[str]:
        """Get list of available OpenAI models"""
        try:
            client = openai.OpenAI(api_key=api_key)
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.models.list()
            )
            return [model.id for model in response.data]
        except Exception as e:
            self.logger.error(f"Error fetching OpenAI models: {e}")
            return []
