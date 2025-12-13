"""MCP Server with HTTP transport and Keycloak OIDC authentication."""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the same directory as this script
load_dotenv(Path(__file__).parent / ".env")

import httpx
import jwt
from functools import lru_cache
from pydantic import AnyHttpUrl
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

# OIDC Configuration - same as research-agent
OIDC_ISSUER_URL = os.getenv(
    "OIDC_ISSUER_URL", "http://localhost:8080/realms/gemini-enterprise"
)
OIDC_ISSUER_EXTERNAL = os.getenv("OIDC_ISSUER_EXTERNAL", OIDC_ISSUER_URL)
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "mcp-test-client")
OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", "echo-mcp-server")


@lru_cache(maxsize=1)
def get_jwks() -> dict:
    """Fetch and cache JWKS from Keycloak."""
    jwks_url = f"{OIDC_ISSUER_URL}/protocol/openid-connect/certs"
    response = httpx.get(jwks_url, timeout=10)
    response.raise_for_status()
    return response.json()


def get_public_key(token: str):
    """Get the public key for the token's kid."""
    jwks = get_jwks()
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")

    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(key)

    raise ValueError("Public key not found")


class KeycloakTokenVerifier(TokenVerifier):
    """Verify access tokens from Keycloak OIDC."""

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # Debug: decode without verification first
            unverified = jwt.decode(token, options={"verify_signature": False})
            print(f"[DEBUG] Token issuer: {unverified.get('iss')}")
            print(f"[DEBUG] Token audience: {unverified.get('aud')}")
            print(f"[DEBUG] Token azp: {unverified.get('azp')}")
            print(f"[DEBUG] Expected issuer: {OIDC_ISSUER_EXTERNAL}")
            print(f"[DEBUG] Expected audience: {OIDC_AUDIENCE}")

            public_key = get_public_key(token)
            # Verify token - skip audience check if not present (dynamic client registration)
            token_aud = unverified.get("aud")
            if token_aud:
                claims = jwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256"],
                    issuer=OIDC_ISSUER_EXTERNAL,
                    audience=OIDC_AUDIENCE,
                )
            else:
                # No audience in token - verify without audience check
                claims = jwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256"],
                    issuer=OIDC_ISSUER_EXTERNAL,
                    options={"verify_aud": False},
                )
            print(f"[DEBUG] Token verified successfully!")
            # client_id can be from azp (authorized party) or aud
            client_id = claims.get("azp") or claims.get("aud") or "unknown"
            return AccessToken(
                token=token,
                client_id=client_id,
                scopes=claims.get("scope", "").split(),
                expires_at=claims.get("exp"),
            )
        except jwt.ExpiredSignatureError as e:
            print(f"[DEBUG] Token expired: {e}")
            return None
        except jwt.InvalidTokenError as e:
            print(f"[DEBUG] Invalid token: {e}")
            return None
        except Exception as e:
            print(f"[DEBUG] Token verification error: {e}")
            return None


# Set AUTH_ENABLED=1 to enable Keycloak auth (requires ngrok or trusted host)
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "0") == "1"

if AUTH_ENABLED:
    mcp = FastMCP(
        "Secure MCP Server",
        json_response=True,
        token_verifier=KeycloakTokenVerifier(),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(OIDC_ISSUER_EXTERNAL),
            resource_server_url=AnyHttpUrl(
                os.getenv("RESOURCE_SERVER_URL", "http://localhost:8001")
            ),
            required_scopes=[],
        ),
    )
else:
    # No auth for local development
    mcp = FastMCP("Secure MCP Server", json_response=True, stateless_http=True)


@mcp.tool()
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    import uvicorn

    print(f"Auth enabled: {AUTH_ENABLED}")
    if AUTH_ENABLED:
        print(f"OIDC Issuer: {OIDC_ISSUER_EXTERNAL}")
        print(f"OIDC Client ID: {OIDC_CLIENT_ID}")
        print(f"OIDC Audience: {OIDC_AUDIENCE}")
        print(f"Resource Server URL: {os.getenv('RESOURCE_SERVER_URL', 'http://localhost:8001')}")
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=8001)
