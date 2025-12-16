# Keycloak Standalone Setup

## Prerequisites

Ensure you have activated the virtual environment from the parent directory:

```bash
source ../.venv/bin/activate
```

## Configuration

### Setting KC_HOSTNAME

Before starting Keycloak, update `KC_HOSTNAME` in `docker-compose.yml` to match your host:

- For local development: `KC_HOSTNAME: localhost`
- For ngrok tunnels: `KC_HOSTNAME: your-subdomain.ngrok-free.app`
- For custom domains: `KC_HOSTNAME: your-domain.com`

Example:
```yaml
environment:
  KC_HOSTNAME: localhost  # Change this to your hostname
```

## Setup Instructions

1. Start Keycloak:

```bash
docker-compose up -d
```

2. Navigate to the keycloak directory and run the setup script:

```bash
cd keycloak-standalone
python setup_keycloak.py --config config.json --url http://localhost:8080
```

### Disable "Host Sending Client Registration Request Must Match"

For dynamic client registration to work from different hosts, you need to disable the Trusted Hosts policy:

1. Open Keycloak Admin Console: http://localhost:8080/admin
2. Login with `admin` / `admin`
3. Select your realm (e.g., `mcp-realm`)
4. Go to **Realm Settings** → **Client Registration** → **Client Registration Policies**
5. Under **Anonymous Access Policies**, find **Trusted Hosts**
6. Click the trash icon to delete this policy

This allows clients from any host to register dynamically without hostname validation.

## References

- [Understanding MCP Authorization with Dynamic Client Registration](https://blog.christianposta.com/understanding-mcp-authorization-with-dynamic-client-registration/)
- [MCP Auth Step by Step Guide](https://github.com/christian-posta/mcp-auth-step-by-step)