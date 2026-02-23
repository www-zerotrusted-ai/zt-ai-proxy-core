# Standalone runtime helpers stub

def load_config():
    return {}

def run_async_in_thread(fn, *args, **kwargs):
    return fn(*args, **kwargs)

def domain_matches(domain, pattern):
    return False

def get_cached_blocklist():
    return []

def get_cached_whitelist():
    return []

def get_cached_enforcement_type():
    return None

def features_refresh_loop():
    pass

def get_features_cache_info():
    return {}

def get_blocklist_cache_info():
    return {}

def clear_all_in_memory_caches():
    pass

BLOCKLIST_TTL_SEC = 3600
