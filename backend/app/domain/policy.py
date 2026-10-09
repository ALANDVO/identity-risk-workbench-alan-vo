"""Parse user-editable analysis policy without accepting silent coercions."""
from dataclasses import asdict
from .analysis import validate_policy
from .models import Policy, ToxicPair


def parse_policy(data: dict | None) -> Policy:
    if data is None:
        return Policy()
    if not isinstance(data, dict):
        raise ValueError("Policy must be an object")
    allowed = set(asdict(Policy()))
    if set(data) - allowed:
        raise ValueError("Unknown policy fields")
    values = dict(data)
    if "concentration_threshold" in values:
        value = values["concentration_threshold"]
        if type(value) not in (float, int):
            raise ValueError("Concentration threshold must be numeric")
    if "privileged_permissions" in values:
        perms = values["privileged_permissions"]
        if not isinstance(perms, list) or any(not isinstance(p, str) for p in perms):
            raise ValueError("Privileged permissions must be a list of permission strings")
        if len(set(perms)) != len(perms):
            raise ValueError("Privileged permissions must be unique")
        values["privileged_permissions"] = tuple(perms)
    if "toxic_pairs" in values:
        pairs = values["toxic_pairs"]
        if not isinstance(pairs, list) or len(pairs) > 30:
            raise ValueError("Toxic pairs must be a list of at most 30 rules")
        if any(not isinstance(p, dict) or set(p) != {"name", "left", "right"} for p in pairs):
            raise ValueError("Each toxic pair needs name, left and right")
        if any(not isinstance(p[k], str) for p in pairs for k in ("name", "left", "right")):
            raise ValueError("Toxic pair fields must be strings")
        values["toxic_pairs"] = tuple(ToxicPair(**p) for p in pairs)
    policy = Policy(**values)
    validate_policy(policy)
    return policy
