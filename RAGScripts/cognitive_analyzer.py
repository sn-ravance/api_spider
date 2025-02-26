from typing import Dict, List
import asyncio
from .utils.logger import setup_logger
from .utils.pattern_extractor import PatternExtractor
from .llm_analyzer import LLMAnalyzer
from .utils.prompt_templates import (
    SECURITY_ANALYSIS_TEMPLATE,
    BEHAVIOR_ANALYSIS_TEMPLATE,
    METHOD_ANALYSIS_TEMPLATE
)

class CognitiveAnalyzer:
    def __init__(self, verbosity: int = 0, llm: str = 'ollama', model: str = 'llama2'):
        self.response_history = []
        self.vulnerability_patterns = {}
        self.verbosity = verbosity
        self.logger = setup_logger("cognitive_analyzer", verbosity)
        self.pattern_extractor = PatternExtractor()
        self.llm_analyzer = LLMAnalyzer(
            openai_key=None if llm == 'ollama' else os.getenv('OPENAI_API_KEY'),
            ollama_host="http://localhost:11434"
        )
        self.llm_analyzer.ollama_model = model

    async def analyze_endpoint_behavior(self, url: str, responses: List[Dict]) -> Dict:
        """Enhanced endpoint behavior analysis"""
        if self.verbosity >= 2:
            self.logger.debug(f"Starting analysis for endpoint: {url}")

        # Extract patterns from responses
        patterns = []
        for resp in responses:
            extracted = self.pattern_extractor.extract_pattern(str(resp))
            normalized = self.pattern_extractor.normalize_response(str(resp))
            patterns.append({
                "patterns": extracted,
                "normalized": normalized
            })

        # Basic behavior analysis
        behavior = self._analyze_basic_behavior(responses)
        
        # Prepare context for LLM analysis
        context = {
            "url": url,
            "responses": responses,
            "patterns": patterns,
            "behavior": behavior,
            "history": self.response_history[-10:] if self.response_history else [],
            "false_positives": self._get_known_false_positives()
        }

        try:
            # Perform multi-stage analysis
            security_analysis = await self.llm_analyzer.analyze_endpoint(
                url,
                context,
                SECURITY_ANALYSIS_TEMPLATE
            )

            behavior_analysis = await self.llm_analyzer.analyze_endpoint(
                url,
                context,
                BEHAVIOR_ANALYSIS_TEMPLATE
            )

            method_analysis = await self.llm_analyzer.analyze_endpoint(
                url,
                context,
                METHOD_ANALYSIS_TEMPLATE
            )

            # Combine and validate results
            combined_results = self._combine_analyses(
                security_analysis,
                behavior_analysis,
                method_analysis
            )

            if self.verbosity >= 2:
                self.logger.debug(f"Analysis results: {combined_results}")

            return combined_results

        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            return {"error": str(e), "confidence": 0.0}

    def _analyze_basic_behavior(self, responses: List[Dict]) -> Dict:
        """Analyze basic response patterns"""
        behavior = {
            "accepts_json": False,
            "requires_auth": False,
            "input_validation": False,
            "error_verbose": False,
            "response_patterns": {},
            "status_distribution": {}
        }

        for resp in responses:
            status = resp.get("status_code", 0)
            behavior["status_distribution"][status] = behavior["status_distribution"].get(status, 0) + 1

            if "application/json" in str(resp.get("headers", {})):
                behavior["accepts_json"] = True
            if status in [401, 403]:
                behavior["requires_auth"] = True
            if "validation" in str(resp.get("response", "")):
                behavior["input_validation"] = True
            if any(x in str(resp.get("response", "")) for x in ["stack", "trace", "error"]):
                behavior["error_verbose"] = True

        return behavior

    def _combine_analyses(self, security: Dict, behavior: Dict, method: Dict) -> Dict:
        """Combine and validate multiple analyses"""
        combined = {
            "security_score": security.get("security_score", 0.0),
            "vulnerabilities": security.get("vulnerabilities", []),
            "behavior_patterns": behavior,
            "recommended_methods": method.get("recommended_methods", []),
            "confidence": min(
                security.get("confidence", 0.0),
                behavior.get("confidence", 0.0),
                method.get("confidence", 0.0)
            ),
            "recommendations": []
        }

        # Combine recommendations
        combined["recommendations"].extend(security.get("recommendations", []))
        combined["recommendations"].extend(behavior.get("recommendations", []))
        combined["recommendations"].extend(method.get("recommendations", []))

        return combined

    def _get_known_false_positives(self) -> List[Dict]:
        """Return known false positive patterns"""
        return [
            {
                "pattern": "Invalid credentials",
                "context": "Authentication endpoint",
                "reason": "Expected authentication failure response"
            },
            {
                "pattern": "Rate limit exceeded",
                "context": "Any endpoint",
                "reason": "Expected rate limiting behavior"
            }
        ]

    def learn_from_response(self, response: Dict) -> None:
        """Learn from responses to improve future analysis"""
        if self.verbosity >= 2:
            self.logger.debug(f"Learning from response: {response}")

        self.response_history.append(response)
        
        if len(self.response_history) > 10:
            self._update_patterns()

    def _update_patterns(self) -> None:
        """Update vulnerability detection patterns"""
        if self.verbosity >= 2:
            self.logger.debug("Updating vulnerability patterns")

        patterns = {}
        for resp in self.response_history[-10:]:
            extracted = self.pattern_extractor.extract_pattern(str(resp))
            for category, findings in extracted.items():
                if category not in patterns:
                    patterns[category] = set()
                patterns[category].update(findings)

        self.vulnerability_patterns = {
            category: list(patterns_set)
            for category, patterns_set in patterns.items()
        }

        if self.verbosity >= 3:
            self.logger.debug(f"Updated patterns: {self.vulnerability_patterns}")