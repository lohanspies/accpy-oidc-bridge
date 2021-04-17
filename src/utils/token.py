import jwt
#Todo - fix RSAKey
# from oidc_provider.models import RSAKey
# from django.utils import timezone
from datetime import datetime
from datetime import timedelta


def build_jwt(
    claims: dict,
    not_before: int,
    not_after: int,
    audience: str,
    issuer: str,
    #TODO - replace RSAKey generation
    # key: RSAKey,
    algorithm: str = "RS256",
) -> str:
    mandatory_claims = {
        "aud": audience,
        "iss": issuer,
        "iat": datetime.now(),
        "nbf": not_before,
        "exp": not_after,
    }

    claims.update(mandatory_claims)
    encoded_jwt = jwt.encode(claims, key, algorithm=algorithm)

    return encoded_jwt.decode("utf-8")


def token(lifetime, issuer, audiences, claims, kid: str):
    not_before = datetime.now()
    not_after = datetime.now() + timedelta(minutes=lifetime)

    #TODO - fix RSA Key
    # key = [x for x in RSAKey.objects.all() if x.kid == kid]
    # if not key:
    #     raise Exception(f"Key with kid {kid} not found")

    jwt_token = build_jwt(
        claims=claims,
        not_before=not_before,
        not_after=not_after,
        audience=audiences,
        issuer=issuer,
        #TODO - Fix RSA key
        # key=key[0].key,
    )

    return jwt_token
