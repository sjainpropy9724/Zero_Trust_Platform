import requests
import json
from app.schemas.policy_schemas import AccessContext

OPA_URL = "http://opa:8181/v1/data/main" # 'opa' is the service name in docker-compose

def evaluate_request(context: AccessContext) -> dict:
    """
    Sends the context to the OPA engine and returns the decision.
    """
    payload = {"input": context.model_dump()}
    print(f"DEBUG: Sending to OPA: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(OPA_URL, json=payload, timeout=2.0)
        response.raise_for_status()
        
        result = response.json().get("result", {})
        allowed = result.get("allow", False)
        reasons = result.get("deny_reasons", [])
        
        return {"allow": allowed, "reasons": reasons}

    except requests.exceptions.RequestException as e:
        # FALLBACK: If OPA is down, what do we do? Default DENY for security.
        print(f"CRITICAL: OPA Policy Engine is unreachable: {e}")
        return {"allow": False, "reasons": ["Internal Security Error: Policy Engine Unreachable"]}