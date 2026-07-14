import hmac


def token_is_valid(authorization: str | None, expected_token: str) -> bool:
    if not authorization or not expected_token or not authorization.startswith("Bearer "):
        return False
    return hmac.compare_digest(authorization[7:], expected_token)
