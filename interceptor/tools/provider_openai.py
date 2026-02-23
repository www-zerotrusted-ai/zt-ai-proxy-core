# Standalone OpenAI provider stub


def host_is_openai(host):
    # Returns True if the host matches OpenAI domains
    host = host.lower()
    return (
        host.endswith('openai.com') or
        host == 'api.openai.com' or
        host == 'chat.openai.com' or
        host == 'platform.openai.com'
    )


def is_openai_chat_path(path):
    # Returns True if the path matches OpenAI chat/completions endpoints
    # e.g. /v1/chat/completions, /v1/completions, /backend-api/conversation
    if not path:
        return False
    path = path.lower()
    return (
        path.startswith('/v1/chat/completions') or
        path.startswith('/v1/completions') or
        path.startswith('/backend-api/conversation')
    )


def extract_openai_chat_text(request):
    # Try to extract the prompt or messages from OpenAI request
    if isinstance(request, dict):
        if 'messages' in request and isinstance(request['messages'], list):
            # Chat API: concatenate all message contents
            return ' '.join(
                m.get('content', '') for m in request['messages'] if isinstance(m, dict)
            )
        elif 'prompt' in request:
            # Completion API
            return str(request['prompt'])
    return ""
