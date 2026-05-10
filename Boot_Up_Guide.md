# Judge Boot Guide - MCP Risk Cockpit

This document explains how to boot and demo the project for judges from a fresh local clone.

Repository:

```text
https://github.com/AlohaJarren/Generative-UI-Global-Hackathon-Starter-Kit
```

Primary demo route:

```text
http://localhost:3010/risk-cockpit
```

## 1. What this app is

MCP Risk Cockpit is a generative security interface for AI agents that use MCP tools.

The flow is:

```text
User prompt -> Gemini-generated JSON UI spec -> safe React component registry -> interactive security cockpit
```

Instead of only returning text, the app creates a decision workspace. Depending on the prompt, it can render attack paths, tool risk cards, human approval queues, prompt injection simulations, evidence timelines, policy previews, risk registers, remediation roadmaps, and decision impact summaries.

The most important feature is the Decision Impact Engine. When a judge clicks Approve, Quarantine, or Deny, the app creates a risk reduction estimate, audit packet, policy delta, remediation tasks, owner/SLA, and business impact story.

## 2. Prerequisites

Install these before running the app:

```text
Node.js and npm
Docker Desktop or Docker Engine
Python 3.12
uv
Git
A Gemini API key
A CopilotKit license token
A Notion integration token and duplicated Notion database
```

Recommended local environment:

```text
WSL Ubuntu on Windows, or macOS/Linux
Node managed through nvm
Docker running before npm run dev
```

Check your tools:

```bash
node -v
npm -v
docker --version
docker compose version
python3 --version
uv --version
```

## 3. Clone the repo

```bash
git clone https://github.com/AlohaJarren/Generative-UI-Global-Hackathon-Starter-Kit.git
cd Generative-UI-Global-Hackathon-Starter-Kit
```

If the repo is already cloned:

```bash
cd ~/Generative-UI-Global-Hackathon-Starter-Kit
git pull
```

## 4. Install dependencies

```bash
npm install
```

If `uv` is missing:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
uv --version
```

## 5. Create env files

Copy the example env file:

```bash
cp .env.example .env
```

Open it:

```bash
nano .env
```

Fill in the required values:

```bash
GEMINI_API_KEY=<your Gemini API key>
AGENT_RUNTIME=gemini-flash-deep

COPILOTKIT_LICENSE_TOKEN=<your CopilotKit license token>

INTELLIGENCE_API_URL=http://localhost:4203
INTELLIGENCE_GATEWAY_WS_URL=ws://localhost:4403
INTELLIGENCE_API_KEY=cpk_sPRVSEED_seed0privat0longtoken00

POSTGRES_HOST_PORT=5433
REDIS_HOST_PORT=6381
APP_API_HOST_PORT=4203
REALTIME_GATEWAY_HOST_PORT=4403

LANGGRAPH_DEPLOYMENT_URL=http://localhost:8133
MCP_SERVER_URL=http://localhost:3001/mcp
BFF_URL=http://localhost:4000

NOTION_TOKEN=<your Notion internal integration token>
NOTION_LEADS_DATABASE_ID=<your duplicated Notion database ID>
```

Important notes:

- `LANGGRAPH_DEPLOYMENT_URL` should be `http://localhost:8133` because this repo starts LangGraph on port 8133.
- `BFF_URL` should be `http://localhost:4000` because the BFF starts on port 4000.
- Do not commit `.env` or `apps/agent/.env`.

Sync the env file into the agent app:

```bash
cp .env apps/agent/.env
```

## 6. Get a CopilotKit license token

If `COPILOTKIT_LICENSE_TOKEN` is blank, run:

```bash
npx copilotkit@latest license
```

Copy the full token value into `.env`:

```bash
COPILOTKIT_LICENSE_TOKEN=<token>
```

Then sync again:

```bash
cp .env apps/agent/.env
```

Do not paste the token into Discord, screenshots, or public commits.

## 7. Set up Notion

The starter kit uses a Notion "AI Workshop Provider Community" database.

### Step 1 - Duplicate the Notion database

Open the public sample database from the repo README and duplicate it into your own Notion workspace.

### Step 2 - Create a Notion integration

Go to:

```text
https://notion.so/profile/integrations/internal
```

Create a new internal integration and copy the token. It should start with `ntn_` or `secret_`.

### Step 3 - Share the database with the integration

Open the duplicated database in Notion.

Use:

```text
... menu -> Connections -> Add connection -> select your integration
```

This must be done on the actual source database, not only a linked database view.

### Step 4 - Get the database ID

From a Notion database URL like:

```text
https://www.notion.so/c30e0aeaa8798201a1a7013b5e9dce64?v=...
```

Use only the 32-character ID before `?v=`:

```bash
NOTION_LEADS_DATABASE_ID=c30e0aeaa8798201a1a7013b5e9dce64
```

Then sync:

```bash
cp .env apps/agent/.env
```

## 8. Run the preflight check

```bash
npm run check-env
```

If it passes without output, continue.

If it fails with Notion database access errors, re-check:

```text
1. The integration token is in both .env and apps/agent/.env.
2. The database was shared directly with the integration.
3. The ID has no ?v= suffix.
4. The database is the original database, not a linked view.
```

## 9. Start the app

```bash
npm run dev
```

Expected services:

```text
Frontend: http://localhost:3010
BFF:      http://localhost:4000
Agent:    http://127.0.0.1:8133
Docker:   Postgres, Redis, CopilotKit Intelligence
```

The command starts the Docker intelligence infra, Next.js frontend, Hono/CopilotKit BFF, and LangGraph agent.

## 10. Open the judge demo route

Open:

```text
http://localhost:3010/risk-cockpit
```

This is the main demo route.

## 11. Judge demo script

### Prompt 1 - Full enterprise cockpit

```text
Generate an enterprise MCP security cockpit that shows attack paths, approval gates, blast radius, audit evidence, and the next controls to implement.
```

Point out that the UI is generated from the prompt. The model chooses sections from the safe component registry.

### Prompt 2 - Red-team workspace

```text
Create a red-team investigation workspace for prompt injection, MCP tool poisoning, and data exfiltration across the MCP inventory.
```

Point out attack paths, simulations, and controls.

### Prompt 3 - Executive risk board

```text
Generate an executive risk board that explains business impact, high-risk tools, approval decisions, and compliance gaps.
```

Point out that the same MCP inventory turns into an executive risk view.

### Prompt 4 - Human-in-the-loop approval center

```text
Build a human-in-the-loop approval center for every MCP tool that can write data, execute code, change identity, issue refunds, or post messages.
```

Then click:

```text
Approve
Quarantine
Deny
```

Point out that every decision creates consequences in the Decision Impact Engine:

```text
risk delta
remediation roadmap
owner and SLA
policy delta
audit packet
before vs after story
```

This is the key judge moment. The app is not just visualizing risk. It is turning human decisions into security work.

## 12. Demo pitch

```text
MCP Risk Cockpit turns agent tool access into a human-centered security control surface. As agents gain access to MCP tools that can read data, write records, execute workflows, change identity, or issue financial actions, organizations need more than a chatbot answer. They need generated interfaces that show blast radius, attack paths, approval gates, audit evidence, and remediation work. This app lets the model generate the right interface for the current risk decision, then turns Approve, Quarantine, and Deny into actionable governance.
```

## 13. Troubleshooting

### CopilotKit proxy points to port 4010

Symptom:

```text
Failed to proxy http://localhost:4010/api/copilotkit/info
ECONNREFUSED 127.0.0.1:4010
```

Fix `.env`:

```bash
BFF_URL=http://localhost:4000
```

If it still happens, verify `apps/frontend/next.config.ts` uses `http://localhost:4000`, not `http://localhost:4010`.

Then clear Next cache:

```bash
rm -rf apps/frontend/.next
npm run dev
```

### Gemini API key blocked

Symptom:

```text
API_KEY_SERVICE_BLOCKED
Requests to generativelanguage.googleapis.com are blocked
```

Fix:

```text
1. Create a new Gemini API key in Google AI Studio.
2. Use a personal project, not a locked school/work project.
3. Make sure Generative Language API is allowed.
4. Put the key in GEMINI_API_KEY.
5. Clear or unset GOOGLE_API_KEY if it points to an older key.
```

Then:

```bash
unset GOOGLE_API_KEY
cp .env apps/agent/.env
npm run dev
```

### Notion MCP retrieve data source fails

Symptom:

```text
FAIL: dataSources.retrieve raised
```

Fix:

```text
1. Confirm direct Notion API access works.
2. Confirm the database has a data_sources entry.
3. Confirm the integration is shared with the source database.
```

Keep the `OPENAPI_MCP_HEADERS` patch in `apps/agent/src/notion_mcp.py` if Notion MCP errors appear.

### CopilotKit Intelligence container unhealthy

Symptom:

```text
container hackathon-intelligence-notion-intelligence-1 is unhealthy
error: database "intelligence_app" does not exist
```

Fix:

```bash
docker compose --project-directory . -f deployment/docker-compose.yml up -d postgres redis

docker compose --project-directory . -f deployment/docker-compose.yml exec -T postgres   createdb -U intelligence intelligence_app

docker compose --project-directory . -f deployment/docker-compose.yml up -d --force-recreate --wait intelligence

npm run seed
npm run dev
```

If the container is stuck, reset local Docker volumes:

```bash
docker compose --project-directory . -f deployment/docker-compose.yml down -v --remove-orphans
docker compose --project-directory . -f deployment/docker-compose.yml up -d postgres redis

docker compose --project-directory . -f deployment/docker-compose.yml exec -T postgres   createdb -U intelligence intelligence_app

npm run dev
```

### npm install fails because of stale system Node/npm

Use nvm-managed Node instead of Ubuntu apt npm:

```bash
which node
which npm
```

They should point under:

```text
~/.nvm/
```

If not, install or activate Node with nvm before running `npm install`.

### GitHub push asks for username/password

GitHub does not accept normal account passwords for HTTPS pushes. Use one of:

```text
1. GitHub CLI auth with gh auth login
2. SSH remote
3. Personal access token as the HTTPS password
```

If SSH is configured:

```bash
ssh -T git@github.com
git remote set-url origin git@github.com:AlohaJarren/Generative-UI-Global-Hackathon-Starter-Kit.git
git push origin HEAD
```

## 14. Clean shutdown

Stop the dev server:

```text
Ctrl+C
```

Stop Docker infra:

```bash
npm run dev:infra:down
```

Or manually:

```bash
docker compose --project-directory . -f deployment/docker-compose.yml down
```

## 15. Files added for MCP Risk Cockpit

Main files:

```text
apps/frontend/src/app/risk-cockpit/page.tsx
apps/frontend/src/app/risk-cockpit/McpRiskCockpit.tsx
apps/frontend/src/app/risk-cockpit/DecisionImpactCenter.tsx
apps/frontend/src/app/api/risk-cockpit/generate/route.ts
```

Supporting fixes may include:

```text
apps/frontend/next.config.ts
apps/agent/src/notion_mcp.py
deployment/init-db/001-create-intelligence-app.sql
```

## 16. Final judge checklist

Before presenting:

```text
Docker is running
npm run check-env passes
npm run dev is running
Frontend opened at http://localhost:3010/risk-cockpit
Generate UI button works
Decision Impact Engine updates after Approve, Quarantine, and Deny
No .env secrets are committed
```

## 17. One-line closing pitch

```text
MCP Risk Cockpit is a generative UI security layer for agentic tools. It transforms MCP permissions from invisible backend risk into visible, reviewable, and actionable governance.
```
