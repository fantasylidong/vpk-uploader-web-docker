import hmac
import ipaddress
import re


def token_is_valid(authorization: str | None, expected_token: str) -> bool:
    if not authorization or not expected_token or not authorization.startswith("Bearer "):
        return False
    return hmac.compare_digest(authorization[7:], expected_token)


def client_ip_is_allowed(client_ip: str | None, allowed_cidrs: str) -> bool:
    if not allowed_cidrs.strip():
        return True
    if not client_ip:
        return False
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for item in re.split(r"[\s,]+", allowed_cidrs.strip()):
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return True
    return False
