"""Runtime configuration for Phishing Guardian.

All values come from environment variables (loaded from .env locally, or
injected by AgentBase Runtime in production). No secrets are hard-coded.
"""
import os


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# ── LLM provider (GreenNode MaaS is OpenAI-compatible) ──
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_BASE_URL = os.environ.get(
    "LLM_BASE_URL", "https://maas-llm-aiplatform-hcm.api.vngcloud.vn/v1"
)
LLM_TIMEOUT_SECONDS = float(os.environ.get("LLM_TIMEOUT_SECONDS", "60"))

# ── Model assignments (see CLAUDE.md architecture) ──
# Qwen  → Vietnamese language analysis + final report synthesis
# Gemma → structured technical (URL / header / pattern) extraction
# MiniMax → cross-validation / visual analysis
QWEN_MODEL = os.environ.get("QWEN_MODEL", "qwen3.5-27b")
GEMMA_MODEL = os.environ.get("GEMMA_MODEL", "gemma-4-31b-it")
MINIMAX_MODEL = os.environ.get("MINIMAX_MODEL", "minimax-m2.5")
# Vision model for screenshot OCR + visual phishing cues. MiniMax M2.5 is NOT
# multimodal on the platform; Gemma 4 31B-IT and Qwen 3.5 27B both accept images.
VISION_MODEL = os.environ.get("VISION_MODEL", GEMMA_MODEL)

MINIMAX_ENABLED = _flag("MINIMAX_ENABLED", True)

# Disable models' chain-of-thought "thinking" mode. Reasoning models (Qwen 3.5)
# otherwise spend the whole token budget on a hidden trace and return empty
# content. Set DISABLE_THINKING=false to re-enable for debugging.
DISABLE_THINKING = _flag("DISABLE_THINKING", True)

# ── VirusTotal threat intelligence (optional enrichment) ──
# Privacy-safe by design: domain/URL REPUTATION lookups + file SHA-256 HASH
# lookups only — never uploads file bytes or URLs. No key → silently disabled.
VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_ENABLED = _flag("VT_ENABLED", True)
VT_MAX_DOMAINS = int(os.environ.get("VT_MAX_DOMAINS", "3"))   # stay within 4 req/min free tier
VT_TIMEOUT_SECONDS = float(os.environ.get("VT_TIMEOUT_SECONDS", "8"))
# Min engines that must flag a URL/file before we treat it as malicious. On 90+
# engines a single detection is usually noise (even big legit domains get one),
# so require >= 2 to avoid false positives.
VT_MALICIOUS_MIN = int(os.environ.get("VT_MALICIOUS_MIN", "2"))


def vt_configured() -> bool:
    """True when VirusTotal enrichment is enabled and has an API key."""
    return VT_ENABLED and bool(VT_API_KEY)


# ── Microsoft Teams bot (Bot Framework) ──
MICROSOFT_APP_ID = os.environ.get("MICROSOFT_APP_ID", "")
MICROSOFT_APP_PASSWORD = os.environ.get("MICROSOFT_APP_PASSWORD", "")
MICROSOFT_APP_TENANT_ID = os.environ.get("MICROSOFT_APP_TENANT_ID", "")


def teams_configured() -> bool:
    """True when the Teams bot has its app id + secret configured."""
    return bool(MICROSOFT_APP_ID and MICROSOFT_APP_PASSWORD)

# ── Risk scoring weights (sum to 1.0) ──
WEIGHTS = {
    "language": 0.40,    # Qwen findings
    "technical": 0.35,   # Gemma findings
    "visual": 0.25,      # MiniMax findings / cross-validation
}

# Any critical indicator forces the final score into the DANGEROUS band.
# (Brief says "min 70 = Nguy hiểm"; since 70 is still NGHI NGỜ, floor at 71.)
CRITICAL_FLOOR = 71

# Risk band thresholds (inclusive upper bounds for SAFE / SUSPICIOUS).
SAFE_MAX = 30
SUSPICIOUS_MAX = 70


def llm_configured() -> bool:
    """True when we have enough config to call the LLM provider."""
    return bool(LLM_API_KEY and LLM_BASE_URL)
