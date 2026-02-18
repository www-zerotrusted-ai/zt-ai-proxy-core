import json
import re
from typing import Optional


OPENAI_DOMAINS = (
    'openai.com',
    'api.openai.com',
    'chatgpt.com',
    'oaiusercontent.com',
)


OPENAI_CHAT_PATH_REGEX = re.compile(r"(?:/backend-api/(?:f/)?conversation(?:s)?|/v\d+/(?:chat|completions|conversation(?:s)?))", re.I)
FAST_CONVERSATION_REGEX = re.compile(r"/backend-api/f/conversation(?:s)?", re.I)


def host_is_openai(host: str) -> bool:
    h = (host or '').lower()
    return any(h == d or h.endswith('.' + d) for d in OPENAI_DOMAINS)


def is_openai_chat_path(path: str) -> bool:
    try:
        return bool(OPENAI_CHAT_PATH_REGEX.search((path or '').lower()))
    except Exception:
        return False


def is_openai_fast_conversation_path(path: str) -> bool:
    """True for ChatGPT web fast conversation endpoint: /backend-api/f/conversation(s)?"""
    try:
        return bool(FAST_CONVERSATION_REGEX.search((path or '').lower()))
    except Exception:
        return False




def extract_openai_chat_text(body_text: str) -> str:
    """Extract user text from ChatGPT/OpenAI web payloads.

    Prioritizes messages[*].content.parts[*] and common fallbacks.
    Caps length to ~5000 chars.
    """
    if not body_text:
        return ''
    txt = body_text
    try:
        jb = json.loads(body_text)
    except Exception:
        return txt

    if isinstance(jb, dict):
        out: list[str] = []
        msgs = jb.get('messages')
        if isinstance(msgs, list):
            for m in msgs:
                if not isinstance(m, dict):
                    continue
                c = m.get('content')
                if isinstance(c, dict):
                    # ChatGPT web: { content_type: 'text', parts: [ '...' ] }
                    parts = c.get('parts')
                    if isinstance(parts, list):
                        for p in parts:
                            if isinstance(p, str) and p:
                                out.append(p)
                    # Alt shape: { content_type: 'input_text', text: '...' }
                    t = c.get('text')
                    if isinstance(t, str) and t:
                        out.append(t)
                elif isinstance(c, str) and c:
                    out.append(c)
        # Top-level fallbacks
        for k in ('content','text','prompt','input','message'):
            v = jb.get(k)
            if isinstance(v, str) and v:
                out.append(v)
        if out:
            return ('\n'.join(out))[:5000]
    return txt


def extract_openai_raw_payload(body_text: str) -> str:
    """Return the raw request body for OpenAI/ChatGPT payloads (no JSON parsing).

    This is useful for endpoints like /backend-api/f/conversation where the
    payload structure may vary; the PII detector can scan the raw JSON/text.
    Caps length to ~5000 chars.
    """
    if not body_text:
        return ''
    try:
        return body_text[:5000]
    except Exception:
        return body_text
