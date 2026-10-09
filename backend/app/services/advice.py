"""Optional aggregate-only LLM advice with bounded responses and local fallback."""
import json
from urllib.parse import urlsplit
import httpx
from app.core.config import Settings

SYSTEM = ("You advise identity governance reviewers using aggregate counts only. "
          "Give concise priorities, uncertainties, and verification steps. "
          "Do not assert a compromise or invent identities, grant paths, or executed actions. "
          "Risk scores are heuristics, not probabilities. Return plain text, no HTML.")


def local_advice(analysis):
    rules = analysis['summary']['by_rule']
    steps = []
    for rule, instruction in [
        ('toxic_pair', 'Review conflicting duties and all inherited grant paths before removing access.'),
        ('mfa_missing', 'Require MFA for privileged human accounts after validating enrollment data.'),
        ('mfa_unknown', 'Collect MFA evidence; unknown enrollment is not confirmed absence.'),
        ('orphan_service', 'Identify service owners and review operational dependencies.'),
        ('stale', 'Confirm activity coverage and business need before disabling stale accounts.'),
        ('never_used', 'Review accounts without recorded sign-ins, including service account activity outside interactive login.'),
        ('concentration', 'Review concentrated grants against job duties and the limits of permission-string counts.'),
        ('disabled_grants', 'Review retained grants before any account is re-enabled.'),
    ]:
        if rules.get(rule): steps.append(f"{rules[rule]} {rule.replace('_', ' ')} finding(s): {instruction}")
    if not steps: steps = ['No configured rule triggered. Confirm export completeness, policy coverage and unsupported permission conditions.']
    return '\n'.join(steps)


def advise(analysis: dict, settings: Settings, external=False, transport=None):
    result = {'text': local_advice(analysis), 'source': 'local', 'external_sent': False,
              'reason': 'Deterministic guidance; no external request made.'}
    if not external: return result
    provider = settings.llm_provider
    defaults = {'openai': ('https://api.openai.com/v1', 'gpt-4o-mini'),
                'openai-compatible': ('https://api.openai.com/v1', 'gpt-4o-mini'),
                'anthropic': ('https://api.anthropic.com/v1', 'claude-sonnet-4-6'),
                'gemini': ('https://generativelanguage.googleapis.com/v1beta/openai', 'gemini-2.5-flash'),
                'ollama': ('http://127.0.0.1:11434/v1', 'llama3.2')}
    if provider not in defaults:
        return result | {'reason': 'Unknown configured provider; local guidance retained.'}
    if not settings.llm_api_key and provider != 'ollama':
        return result | {'reason': 'LLM_API_KEY is not configured; local guidance retained.'}
    base, model = defaults[provider]
    base = (settings.llm_base_url or base).rstrip('/')
    model = settings.llm_model or model
    url = urlsplit(base)
    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
        return result | {'reason': 'Invalid operator-configured LLM endpoint; local guidance retained.'}
    if url.scheme == 'http' and url.hostname not in ('127.0.0.1', 'localhost', '::1'):
        return result | {'reason': 'Remote LLM endpoints require HTTPS; local guidance retained.'}
    payload = json.dumps(analysis['summary'], sort_keys=True)
    headers = {'Content-Type': 'application/json'}
    if provider == 'anthropic':
        endpoint = base + '/messages'
        headers |= {'x-api-key': settings.llm_api_key, 'anthropic-version': '2023-06-01'}
        body = {'model': model, 'max_tokens': 800, 'system': SYSTEM,
                'messages': [{'role': 'user', 'content': payload}]}
    else:
        endpoint = base + '/chat/completions'
        if settings.llm_api_key: headers['Authorization'] = 'Bearer ' + settings.llm_api_key
        body = {'model': model, 'max_tokens': 800, 'messages': [
            {'role': 'system', 'content': SYSTEM}, {'role': 'user', 'content': payload}]}
    try:
        result['external_sent'] = True
        with httpx.Client(timeout=settings.llm_timeout_seconds, transport=transport, follow_redirects=False, trust_env=False) as client:
            with client.stream('POST', endpoint, headers=headers, json=body) as response:
                response.raise_for_status()
                raw = bytearray()
                for part in response.iter_bytes():
                    raw.extend(part)
                    if len(raw) > 128000: raise ValueError('Response exceeds size bound')
                data = json.loads(raw)
        if provider == 'anthropic':
            output = '\n'.join(part['text'] for part in data['content'] if part.get('type') == 'text')
        else: output = data['choices'][0]['message']['content']
        if not isinstance(output, str) or not output.strip(): raise ValueError('Empty advice')
        if settings.llm_api_key: output = output.replace(settings.llm_api_key, '[redacted]')
        return {'text': output[:12000], 'source': 'llm', 'external_sent': True,
                'reason': 'Aggregate counts only were sent. Treat generated advice as unverified suggestions.'}
    except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError, AttributeError):
        return result | {'reason': 'Provider request or response failed; local guidance retained. No upstream response details exposed.'}
