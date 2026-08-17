"""
Bot Challenge & WAF Interstitial Classifier for PULSE Web Subsystem.

Detects security interstitials (Cloudflare "Just a moment...", Akamai Bot Manager,
AWS WAF Captcha, Incapsula) to prevent misattributing challenge screens to target web stacks.
"""

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class ChallengeDetectionResult:
    is_challenge: bool
    provider: Optional[str] = None
    reason: Optional[str] = None
    status_code: Optional[int] = None


class BotChallengeDetector:
    """Identifies bot-protection and WAF challenge interstitials."""

    CHALLENGE_SIGNATURES = [
        # Cloudflare Challenge Screen
        {
            "provider": "Cloudflare Bot Management",
            "html_patterns": [
                r"Just a moment\.\.\.",
                r"Checking your browser before accessing",
                r"cf-chl-bypass",
                r"cf-spinner",
                r"_cf_chl_opt",
                r"challenge-platform/scripts",
                r"cf-browser-verification",
                r"Cloudflare Ray ID:"
            ],
            "header_patterns": {
                "server": r"cloudflare",
                "cf-mitigated": r"challenge"
            },
            "status_codes": [403, 429, 503]
        },
        # Akamai Bot Manager
        {
            "provider": "Akamai Bot Manager",
            "html_patterns": [
                r"ak_bmsc",
                r"_abck",
                r"Access Denied - Akamai",
                r"bm-telemetry"
            ],
            "header_patterns": {
                "server": r"AkamaiGHost"
            },
            "status_codes": [403, 429]
        },
        # AWS WAF Captcha / Challenge
        {
            "provider": "AWS WAF",
            "html_patterns": [
                r"awswaf",
                r"aws-waf-captcha",
                r"AWS WAF Captcha"
            ],
            "header_patterns": {
                "x-amzn-waf-action": r"captcha|challenge"
            },
            "status_codes": [403, 405]
        },
        # Imperva Incapsula Block
        {
            "provider": "Imperva Incapsula",
            "html_patterns": [
                r"_Incapsula_Resource",
                r"Incapsula incident ID",
                r"Request unsuccessful\. Incapsula incident"
            ],
            "header_patterns": {
                "x-iinfo": r".*"
            },
            "status_codes": [403]
        }
    ]

    @classmethod
    def inspect(
        cls,
        status_code: int,
        headers: Dict[str, str],
        html_body: str
    ) -> ChallengeDetectionResult:
        """
        Inspects an HTTP response for bot-challenge interstitials.
        """
        norm_headers = {k.lower().strip(): v for k, v in headers.items()}
        body = html_body or ""

        for sig in cls.CHALLENGE_SIGNATURES:
            provider = sig["provider"]
            
            # 1. Match HTML markers
            html_matches = 0
            for pattern in sig["html_patterns"]:
                if re.search(pattern, body, re.IGNORECASE):
                    html_matches += 1

            # 2. Match Header markers
            header_matches = 0
            for h_key, h_pattern in sig.get("header_patterns", {}).items():
                if h_key in norm_headers and re.search(h_pattern, norm_headers[h_key], re.IGNORECASE):
                    header_matches += 1

            # Check if this matches a challenge threshold
            if (html_matches >= 2) or (html_matches >= 1 and status_code in sig["status_codes"]) or (html_matches >= 1 and header_matches >= 1):
                reason = f"Security interstitial detected from {provider} (HTTP {status_code}). Automated scan blocked by bot protection."
                return ChallengeDetectionResult(
                    is_challenge=True,
                    provider=provider,
                    reason=reason,
                    status_code=status_code
                )

        return ChallengeDetectionResult(is_challenge=False)
