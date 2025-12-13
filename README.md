# MCP Server with OIDC Auth

A Model Context Protocol (MCP) server implementation with OpenID Connect authentication.

## Setup

1. Navigate to the project directory:

```bash
cd mcp-auth
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Server

Start the MCP server:

```bash
python server.py
```

The server will be available at `http://localhost:8000/mcp`

## Testing

Test the server with a curl request:

```bash
curl -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

## Project Structure

- `server.py` - Main MCP server implementation
- `requirements.txt` - Python dependencies
- `keycloak-standalone/` - Keycloak setup for authentication
- `.env.example` - Environment variables template
