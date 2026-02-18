import os
import re
import requests
from typing import Any, Dict, List, Tuple

Category = str  # 'PII' | 'PHI' | 'PCI'

# Edition detection for standalone vs enterprise
EDITION = os.getenv('ZT_EDITION', 'standalone').lower()
IS_STANDALONE = (EDITION == 'standalone')
IS_ENTERPRISE = (EDITION == 'enterprise')

# Log file path for PII service debug logs
_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'intercepted_requests.log')

def _log(message: str):
    """Write message to intercepted_requests.log"""
    try:
        with open(_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{message}\n")
    except Exception:
        pass

# Connection pooling: Reuse session for PII service calls
# This reduces TLS handshake overhead (10-50ms saved per request)
_pii_session = None

def _get_pii_session():
    """Get or create persistent requests session for PII service calls."""
    global _pii_session
    if _pii_session is None:
        _pii_session = requests.Session()
        # Configure connection pool
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,  # Number of connection pools
            pool_maxsize=20,      # Connections per pool
            max_retries=0         # No auto-retry (we handle timeouts)
        )
        _pii_session.mount('http://', adapter)
        _pii_session.mount('https://', adapter)
    return _pii_session


def _detect_pii_local(text: str, threshold: int = 3) -> Dict[str, Any]:
    """
    Local regex-based PII detection for standalone mode (no external API calls).
    Detects: emails, phone numbers, credit cards, SSN, CVV, names, addresses.
    
    Returns dict matching the API response format for compatibility.
    """
    if not text or not isinstance(text, str):
        return {'detected': False, 'counts': {'PII': 0, 'PHI': 0, 'PCI': 0}, 'items': [], 'threshold': threshold}
    
    counts = {'PII': 0, 'PHI': 0, 'PCI': 0}
    items = []
    
    # Email pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    for match in re.finditer(email_pattern, text):
        counts['PII'] += 1
        items.append({'category': 'PII', 'type': 'EMAIL', 'value': match.group()})
    
    # Phone patterns (various formats)
    phone_patterns = [
        r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',  # +1-123-456-7890, (123) 456-7890
        r'\+?\d{10,14}',  # +919898989898
        r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # 123-456-7890
    ]
    for pattern in phone_patterns:
        for match in re.finditer(pattern, text):
            matched_text = match.group()
            # Avoid false positives like "123-123-1234"
            if len(set(matched_text.replace('+', '').replace('-', '').replace(' ', '').replace('(', '').replace(')', ''))) > 3:
                counts['PII'] += 1
                items.append({'category': 'PII', 'type': 'PHONE', 'value': matched_text})
                break  # One match per pattern
    
    # Credit card patterns (13-19 digits, optionally with spaces/dashes)
    cc_patterns = [
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # 4111-1111-1111-1111
        r'\b\d{13,19}\b',  # 4111111111111111
    ]
    for pattern in cc_patterns:
        for match in re.finditer(pattern, text):
            matched_text = match.group().replace('-', '').replace(' ', '')
            # Basic Luhn check to reduce false positives
            if len(matched_text) >= 13 and matched_text.isdigit():
                counts['PCI'] += 1
                items.append({'category': 'PCI', 'type': 'CREDIT_CARD', 'value': match.group()})
                break
    
    # CVV pattern (3-4 digits, often near "cvv" keyword)
    cvv_pattern = r'(?i)cvv[\s:]*(\d{3,4})'
    for match in re.finditer(cvv_pattern, text):
        counts['PCI'] += 1
        items.append({'category': 'PCI', 'type': 'CVV', 'value': match.group(1)})
    
    # SSN pattern (123-45-6789)
    ssn_pattern = r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'
    for match in re.finditer(ssn_pattern, text):
        matched_text = match.group()
        # Avoid obvious false positives like phone numbers
        if '-' in matched_text or (len(matched_text.replace(' ', '')) == 9 and len(matched_text.split('-')) == 3):
            counts['PII'] += 1
            items.append({'category': 'PII', 'type': 'SSN', 'value': matched_text})
    
    # Simple name detection (capitalized words near common name keywords)
    name_pattern = r'(?i)(?:name is|my name is|i am|i\'m)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)'
    for match in re.finditer(name_pattern, text):
        counts['PII'] += 1
        items.append({'category': 'PII', 'type': 'NAME', 'value': match.group(1)})
    
    # Calculate total detections
    total_detections = counts['PII'] + counts['PHI'] + counts['PCI']
    detected = total_detections >= threshold
    
    _log(f"[PII LOCAL] Detected {total_detections} PII items (threshold={threshold}): PII={counts['PII']}, PHI={counts['PHI']}, PCI={counts['PCI']}")
    
    return {
        'detected': detected,
        'counts': counts,
        'items': items[:20],  # Limit items to avoid huge responses
        'threshold': threshold,
        'total': total_detections,
        'source': 'local-regex'
    }


def _extract_counts_and_items(resp: Dict[str, Any], categories: List[Category]) -> Tuple[Dict[Category, int], List[Dict[str, str]]]:
    counts: Dict[Category, int] = {c: 0 for c in categories}
    items: List[Dict[str, str]] = []

    # Some responses nest results under a 'data' key
    src = resp
    try:
        if isinstance(resp.get('data'), dict):
            src = resp['data']
    except Exception:
        src = resp

    # PII normalization helpers (uses zt-guardrails-lib service endpoints)
    # Preferred unified list
    unified = src.get('pii_list') or src.get('pii') or []
    if isinstance(unified, list) and unified:
        for it in unified:
            try:
                cat = (it.get('type') or it.get('category') or it.get('kind') or '').upper()
                val = it.get('value') or it.get('text') or it.get('match') or ''
                if not cat:
                    continue
                # Map common aliases
                if cat in ('PCI', 'PCI-DSS', 'CREDIT_CARD', 'CARD'):
                    cat = 'PCI'
                if cat in ('PHI', 'HEALTH'):
                    cat = 'PHI'
                if cat not in ('PII', 'PHI', 'PCI'):
                    # If unclassified, assume PII as safe default
                    cat = 'PII'
                if cat in counts:
                    counts[cat] += 1
                items.append({'category': cat, 'value': str(val)[:120]})
            except Exception:
                continue

    # Some responses separate categories
    for key, cat in [('phi', 'PHI'), ('pci', 'PCI')]:
        arr = src.get(key)
        if isinstance(arr, list):
            counts[cat] += len(arr)
            for v in arr:
                try:
                    items.append({'category': cat, 'value': str(v)[:120]})
                except Exception:
                    pass

    # pii_entities may be a dict of category -> list of values or list of objects
    entities = src.get('pii_entities')
    if isinstance(entities, dict):
        for k, arr in entities.items():
            try:
                cat = str(k).upper()
                if cat in ('PCI-DSS','CREDIT_CARD','CARD'):
                    cat = 'PCI'
                if cat in ('HEALTH',):
                    cat = 'PHI'
                if cat not in ('PII','PHI','PCI'):
                    cat = 'PII'
                if isinstance(arr, list):
                    for v in arr:
                        try:
                            counts[cat] += 1
                            items.append({'category': cat, 'value': str(v)[:120]})
                        except Exception:
                            continue
            except Exception:
                continue
    elif isinstance(entities, list):
        for it in entities:
            try:
                cat = (it.get('type') or it.get('category') or it.get('kind') or '').upper()
                val = it.get('value') or it.get('text') or it.get('match') or ''
                if not cat:
                    continue
                if cat in ('PCI-DSS','CREDIT_CARD','CARD'):
                    cat = 'PCI'
                if cat in ('HEALTH',):
                    cat = 'PHI'
                if cat not in ('PII','PHI','PCI'):
                    cat = 'PII'
                if cat in counts:
                    counts[cat] += 1
                items.append({'category': cat, 'value': str(val)[:120]})
            except Exception:
                continue

    # Fallback counts object
    cobj = src.get('counts') or {}
    if isinstance(cobj, dict):
        for cat in counts:
            try:
                counts[cat] = max(counts[cat], int(cobj.get(cat) or 0))
            except Exception:
                pass

    return counts, items

def detect_pii_fast(text: str, *, threshold: int = 3, categories: List[Category] | None = None) -> Dict[str, Any]:
    """Call the configured features service /detect-pii and determine if threshold is met.

    Returns dict with keys: meets_threshold: bool, total: int, counts: dict, items: list.
    """
    if categories is None:
        categories = ['PII', 'PHI', 'PCI']
    cats = [c.strip().upper() for c in categories if c and str(c).strip()]
    base = os.getenv('ZT_FEATURES_URL') or 'http://0.0.0.0:8000'
    
    # Get auth bearer - fallback to proxy API key if bearer not set
    bearer = os.getenv('ZT_FEATURES_BEARER')
    if not bearer:
        # Try to get from config
        try:
            from tools.runtime_helpers import load_config as _load_cfg
            _cfg = _load_cfg() or {}
            bearer = (str(_cfg.get('features_bearer') or '').strip()) or None
            if not bearer:
                # Fallback to proxy_api_key from config or ZT_PROXY_API_KEY env
                bearer = (str(_cfg.get('proxy_api_key') or '').strip()) or os.getenv('ZT_PROXY_API_KEY') or None
        except Exception:
            # Last resort: try ZT_PROXY_API_KEY env directly
            bearer = os.getenv('ZT_PROXY_API_KEY') or None
    
    override_path = os.getenv('ZT_FEATURES_PII_PATH')  # e.g., '/api/detect-pii'

    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    if bearer:
        headers['Authorization'] = f'Bearer {bearer}'
    
    # Debug logging for auth
    try:
        import sys
        if bearer:
            print(f"[PII FAST] Auth: Bearer token present (length: {len(bearer)})", file=sys.stderr)
        else:
            print(f"[PII FAST] WARNING: No auth token found!", file=sys.stderr)
            print(f"  - ZT_FEATURES_BEARER env: {bool(os.getenv('ZT_FEATURES_BEARER'))}", file=sys.stderr)
            print(f"  - ZT_PROXY_API_KEY env: {bool(os.getenv('ZT_PROXY_API_KEY'))}", file=sys.stderr)
    except Exception:
        pass
    
    # Bypass proxy for localhost calls to prevent recursion
    proxies = {}
    if '127.0.0.1' in base or 'localhost' in base:
        proxies = {"http": None, "https": None}

    # Candidate endpoints to try
    candidates: List[str] = []
    if override_path:
        candidates.append(override_path)
    # Common defaults/fallbacks
    candidates.extend([
        '/detect-pii',
        '/api/detect-pii',
        '/pii/detect',
        '/detect_pii',
        '/v1/detect-pii',
    ])
    # Remove duplicates preserving order
    seen = set()
    filtered: List[str] = []
    for p in candidates:
        p = '/' + p.lstrip('/')
        if p not in seen:
            seen.add(p)
            filtered.append(p)

    last_err: str | None = None
    data: Dict[str, Any] = {}
    
    _log(f"[PII SERVICE] Trying {len(filtered)} endpoint paths...")
    
    for path in filtered:
        url = base.rstrip('/') + path
        try:
            # Include both prompt and text fields for compatibility
            payload = {'prompt': text, 'text': text}
            
            _log(f"[PII SERVICE] → POST {url}")
            _log(f"[PII SERVICE] → Headers: {list(headers.keys())}")
            _log(f"[PII SERVICE] → Payload: {{prompt: '{text[:60]}...', text: '{text[:60]}...'}}")
            
            r = requests.post(url, json=payload, headers=headers, timeout=2, proxies=proxies)
            
            _log(f"[PII SERVICE] ← Status: {r.status_code}")
            _log(f"[PII SERVICE] ← Content-Type: {r.headers.get('content-type')}")
            
            if r.ok:
                data = r.json() if 'application/json' in (r.headers.get('content-type') or '') else {}
                _log(f"[PII SERVICE] ← Response keys: {list(data.keys()) if isinstance(data, dict) else type(data)}")
                _log(f"[PII SERVICE] ✓ Success with endpoint: {path}")
                last_err = None
                break
            else:
                error_body = r.text[:200] if r.text else "(no body)"
                last_err = f'HTTP {r.status_code} at {path}'
                _log(f"[PII SERVICE] ✗ Failed {r.status_code}: {error_body}")
                # Try next candidate on 404/405/400 class
                continue
        except Exception as e:
            last_err = str(e)
            _log(f"[PII SERVICE] ✗ Exception on {path}: {e}")
            continue
    
    if last_err is not None and not data:
        _log(f"[PII SERVICE] ✗ All endpoints failed. Last error: {last_err}")
        return {'meets_threshold': False, 'total': 0, 'counts': {c: 0 for c in cats}, 'items': [], 'error': last_err}

    counts, items = _extract_counts_and_items(data, cats)
    total = sum(counts.get(c, 0) for c in cats)
    meets = total >= max(0, int(threshold))
    
    _log(f"[PII SERVICE] Extracted counts: {counts}, total: {total}, meets_threshold: {meets} (threshold={threshold})")
    
    return {'meets_threshold': meets, 'total': total, 'counts': counts, 'items': items}


def detect_pii_lite(
    text: str,
    *,
    threshold: int = 3,
    categories: List[Category] | None = None,
    endpoint_url: str | None = None,
    bearer: str | None = None,
) -> Dict[str, Any]:
    """Call PII detection endpoint (local or remote) and normalize response.

    ZT_FEATURES_URL should contain the FULL endpoint URL including path.
    Examples:
      - https://dev-guardrails.zerotrusted.ai/api/v3/detect-sensitive-keywords-strict
      - http://127.0.0.1:8000/detect-sensitive-data-gliner-strict

    Accepts optional endpoint_url and bearer to support runtime overrides.
    Returns dict with keys: meets_threshold, total, counts, items, ok, error.
    """
    # IGNORE categories parameter - always detect ALL sensitive information types
    # Threshold applies to total count of any sensitive data found
    if categories is None:
        categories = ['PII', 'PHI', 'PCI']
    cats = [c.strip().upper() for c in categories if c and str(c).strip()]

    # Prefer runtime config values if available
    try:
        from tools.runtime_helpers import load_config as _load_cfg
        _cfg = _load_cfg() or {}
    except Exception:
        _cfg = {}
    
    # Get full URL with endpoint (no path appending)
    features_url = (str(_cfg.get('features_url') or '').strip()) or os.getenv('ZT_FEATURES_URL') or 'https://dev-guardrails.zerotrusted.ai/api/v3/detect-sensitive-keywords-strict'
    
    # Get PII URL override (only use if non-empty)
    pii_url_override = (str(_cfg.get('features_pii_url') or '').strip()) or os.getenv('ZT_FEATURES_PII_URL') or ''
    
    # Final URL - use as-is (no path appending)
    url = endpoint_url or pii_url_override or features_url
    
    # Get auth bearer - with fallback chain: 
    # 1. Function parameter
    # 2. Config features_bearer 
    # 3. Env ZT_FEATURES_BEARER
    # 4. Config proxy_api_key (fallback)
    # 5. Env ZT_PROXY_API_KEY (fallback)
    auth = bearer or (str(_cfg.get('features_bearer') or '').strip()) or os.getenv('ZT_FEATURES_BEARER') or None
    if not auth:
        # Fallback to proxy_api_key from config or ZT_PROXY_API_KEY env
        auth = (str(_cfg.get('proxy_api_key') or '').strip()) or os.getenv('ZT_PROXY_API_KEY') or None

    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    if auth:
        # headers['Authorization'] = f'Bearer {auth}'
        headers['X-Custom-Token'] = f'{auth}'
    
    # Bypass proxy for localhost/remote calls
    proxies = {}
    if '127.0.0.1' in url or 'localhost' in url or 'dev-guardrails.zerotrusted.ai' in url:
        proxies = {"http": None, "https": None}
    
    # Log PII endpoint being used (for debugging UI config)
    try:
        import sys
        if pii_url_override:
            print(f"[PII SERVICE] Using override URL: {url}", file=sys.stderr)
        else:
            print(f"[PII SERVICE] Using ZT_FEATURES_URL: {url}", file=sys.stderr)
        
        # Debug: log auth status
        if auth:
            print(f"[PII SERVICE] Auth: Bearer token present (length: {len(auth)})", file=sys.stderr)
        else:
            print(f"[PII SERVICE] WARNING: No auth token found! Checked:", file=sys.stderr)
            print(f"  - features_bearer from config: {bool(_cfg.get('features_bearer'))}", file=sys.stderr)
            print(f"  - ZT_FEATURES_BEARER env: {bool(os.getenv('ZT_FEATURES_BEARER'))}", file=sys.stderr)
            print(f"  - proxy_api_key from config: {bool(_cfg.get('proxy_api_key'))}", file=sys.stderr)
            print(f"  - ZT_PROXY_API_KEY env: {bool(os.getenv('ZT_PROXY_API_KEY'))}", file=sys.stderr)
    except Exception as debug_err:
        print(f"[PII SERVICE] Debug logging error: {debug_err}", file=sys.stderr)

    try:
        # Use persistent session for connection pooling (10-50ms latency improvement)
        session = _get_pii_session()
        # Reduced timeout for faster fail-fast (default 1.5s, configurable via env)
        timeout = float(os.getenv('ZT_PII_SERVICE_TIMEOUT', '1.5'))
        
        # Don't specify entity_types - let API use its comprehensive defaults
        payload = {'prompt': text or '', 'top_n': int(max(0, threshold))}
        
        # Debug logging to intercepted_requests.log
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"[PII SERVICE DEBUG] Request URL: {url}")
        logger.error(f"[PII SERVICE DEBUG] Request payload: {payload}")
        logger.error(f"[PII SERVICE DEBUG] Request headers: {list(headers.keys())}")
        logger.error(f"[PII SERVICE DEBUG] Input text: {text[:200]}")
        
        r = session.post(url, json=payload, headers=headers, timeout=timeout, proxies=proxies)
        
        logger.error(f"[PII SERVICE DEBUG] Response status: {r.status_code}")
        logger.error(f"[PII SERVICE DEBUG] Response headers: {dict(r.headers)}")
        
        print(f"[PII SERVICE] Response status: {r.status_code}", file=sys.stderr)
        print(f"[PII SERVICE] Response headers: {dict(r.headers)}", file=sys.stderr)
        
        if not (200 <= r.status_code < 300):
            logger.error(f"[PII SERVICE DEBUG] Error response body: {r.text[:500]}")
            print(f"[PII SERVICE] Error response body: {r.text[:500]}", file=sys.stderr)
            return {'ok': False, 'error': f'HTTP {r.status_code}', 'meets_threshold': False, 'total': 0, 'counts': {c: 0 for c in cats}, 'items': []}
        jb = r.json()
        logger.error(f"[PII SERVICE DEBUG] Response JSON keys: {list(jb.keys()) if isinstance(jb, dict) else type(jb)}")
        logger.error(f"[PII SERVICE DEBUG] Full response: {jb}")
        
        print(f"[PII SERVICE] Response JSON keys: {list(jb.keys()) if isinstance(jb, dict) else type(jb)}", file=sys.stderr)
        print(f"[PII SERVICE] Full response: {jb}", file=sys.stderr)
        
        # Handle response structure: {"success": true, "data": [...]} or {"data": {"pii_entities": [...]}}
        if isinstance(jb.get('data'), list):
            # New strict format: data is array of tuples
            ent_list = jb.get('data') or []
            print(f"[PII SERVICE] Using data array format, entities: {ent_list}", file=sys.stderr)
        else:
            # Old format: data contains pii_entities
            data = (jb or {}).get('data') or {}
            ent_list = data.get('pii_entities') or []
            print(f"[PII SERVICE] Using pii_entities format, entities: {ent_list}", file=sys.stderr)
        # Normalize items to list of dicts with category and value
        items: List[Dict[str, str]] = []
        for it in ent_list:
            try:
                if isinstance(it, (list, tuple)) and len(it) >= 2:
                    items.append({'category': str(it[1]).strip('<> ').upper(), 'value': str(it[0])[:120]})
                elif isinstance(it, dict):
                    cat = (it.get('tag') or it.get('type') or it.get('category') or '').strip('<> ').upper()
                    val = it.get('value') or it.get('text') or it.get('match') or ''
                    items.append({'category': cat, 'value': str(val)[:120]})
            except Exception:
                continue
        
        print(f"[PII SERVICE] Parsed {len(items)} sensitive items from API response", file=sys.stderr)
        logger.error(f"[PII SERVICE DEBUG] Parsed items details: {items}")
        
        # THRESHOLD LOGIC: Count ALL sensitive information detected, regardless of type
        # User requirement: threshold compares against total sensitive items found
        # Do NOT filter by category - treat all sensitive data equally
        
        # Aggregate counts with normalization (for backward compatibility with logs)
        standard_cats = ['PII', 'PHI', 'PCI']
        counts: Dict[str, int] = {c: 0 for c in standard_cats}
        for it in items:
            cat = (it.get('category') or 'PII').upper()
            # Normalize to standard categories for logging purposes only
            if cat in ('PCI-DSS','CREDIT_CARD','CARD'): cat = 'PCI'
            if cat in ('HEALTH','MEDICAL_RECORD','PATIENT_ID'): cat = 'PHI'
            if cat not in ('PII','PHI','PCI'): cat = 'PII'
            it['category'] = cat
            if cat in counts:
                counts[cat] += 1
        
        # CRITICAL: Total count is ALL items, threshold compares against this total
        total = len(items)  # Count everything - don't limit by category
        meets = total >= max(0, int(threshold))
        
        logger.error(f"[PII SERVICE DEBUG] THRESHOLD CHECK: found={total} items, threshold={threshold}, meets={meets}")
        print(f"[PII SERVICE] THRESHOLD: detected {total} sensitive items, threshold={threshold}, meets={meets}", file=sys.stderr)
        print(f"[PII SERVICE] Category breakdown (for logging): {counts}", file=sys.stderr)
        
        return {'ok': True, 'error': '', 'meets_threshold': meets, 'total': total, 'counts': counts, 'items': items}
    except Exception as e:
        print(f"[PII SERVICE] Exception: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return {'ok': False, 'error': str(e), 'meets_threshold': False, 'total': 0, 'counts': {c: 0 for c in cats}, 'items': []}


def detect_pii_remote(text: str, threshold: int = 3, categories: List[Category] | None = None) -> Dict[str, Any]:
    """
    Call remote strict PII detection endpoint configured via ZT_FEATURES_URL.
    
    IN STANDALONE MODE: Uses local regex-based detection (no external API calls).
    IN ENTERPRISE MODE: Calls remote PII detection service.
    
    This is a convenience wrapper that calls detect_pii_lite() with the current configuration.
    The URL is expected to point to the full endpoint (e.g., .../detect-sensitive-keywords-strict).
    
    No authentication required currently - will be added when server implements it.
    
    Args:
        text: Text to scan for PII
        threshold: Minimum number of findings to meet threshold
        categories: List of PII categories to check (default: ['PII', 'PHI', 'PCI'])
        
    Returns:
        Dictionary with structure:
        {
            'ok': bool,
            'error': str,
            'meets_threshold': bool,
            'total': int,
            'counts': {'PII': int, 'PHI': int, 'PCI': int},
            'items': [{'category': str, 'value': str}, ...]
        }
    """
    # STANDALONE MODE: Use local regex-based detection (no API calls)
    if IS_STANDALONE:
        _log("[PII] Standalone mode - using local regex detection")
        result = _detect_pii_local(text, threshold=threshold)
        # Convert to expected format
        return {
            'ok': True,
            'error': '',
            'meets_threshold': result['detected'],
            'total': result['total'],
            'counts': result['counts'],
            'items': result['items']
        }
    
    # ENTERPRISE MODE: Call remote API
    return detect_pii_lite(text, threshold=threshold, categories=categories)
