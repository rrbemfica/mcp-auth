# Keycloak Standalone Setup

## Prerequisites

Ensure you have activated the virtual environment from the parent directory:

```bash
source ../.venv/bin/activate
```

## Setup Instructions

1. Navigate to the keycloak directory and run the setup script:

```bash
cd keycloak-standalone
python setup_keycloak.py --config config.json --url http://localhost:8080
```

## References

- [Understanding MCP Authorization with Dynamic Client Registration](https://blog.christianposta.com/understanding-mcp-authorization-with-dynamic-client-registration/)
- [MCP Auth Step by Step Guide](https://github.com/christian-posta/mcp-auth-step-by-step)