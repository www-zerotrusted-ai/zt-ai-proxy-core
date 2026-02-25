def is_conversion_api(host, path):
    """
    Returns True if the request is to a known Google conversion/analytics endpoint that should be bypassed for PII/blocking.
    """
    host_lc = (host or '').lower()
    path_lc = (path or '').lower()
    # Google Ads/Conversion endpoints
    if (
        'googleadservices.com' in host_lc or
        'pagead' in path_lc or
        'conversion' in path_lc or
        'doubleclick.net' in host_lc
    ):
        return True
    # Add more analytics/ads endpoints as needed
    return False
# Standalone request filters stub

import re

def is_chat_path(path):
    # Match ChatGPT and Gemini endpoints for blocking (case-insensitive)
    if not path:
        return False
    path_lc = path.lower()
    # ChatGPT
    if path_lc == '/backend-api/f/conversation':
        return True
    # Gemini (Google) endpoints (case-insensitive, allow query params)
    if path_lc.startswith('/_/bardchatui/data/assistant.lamda.bardfrontendservice/streamgenerate') or \
       path_lc.startswith('/_/gemini/data/assistant.lamda.bardfrontendservice/streamgenerate'):
        return True
    return False

def extract_chat_text(request):
    # Try to extract text from request dict or object
    if isinstance(request, dict):
        return request.get("text", "")
    elif hasattr(request, "text"):
        return getattr(request, "text", "")
    return str(request)

def run_pii_gate(request, threshold=1):
    # Improved PII detection: regex for email, phone, card, plus keywords
    text = extract_chat_text(request)
    patterns = [
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",  # email
        r"\b\+?\d{1,3}[\s-]?\d{6,14}\b",  # phone (simple)
        r"\b(?:\d[ -]*?){13,16}\b",  # credit card (simple)
        r"\b\d{3}-\d{4}-\d{4}\b",  # card (custom, like 123-1222-4564)
        r"\b\d{3}\b.*cvv",  # cvv
    ]
    pii_keywords = [
        "password", "ssn", "credit card", "secret", "private key", "api_key", "token", "dob", "date of birth", "passport", "bank", "iban", "account number", "routing number", "email", "phone", "address"
    ]
    found = []
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            found.append(pat)
    for kw in pii_keywords:
        if kw.lower() in text.lower():
            found.append(kw)
    return len(found) >= threshold

def handle_post_only_block(*args, **kwargs):
    return None

def extract_attachments_text(*args, **kwargs):
    return ""
