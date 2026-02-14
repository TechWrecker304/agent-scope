# 🔭 NeatLabs™ Agent Scope

**AI Agent Permission & Access Auditor**

Know exactly what your AI agents can do on your system — before they do it.

Agent Scope scans MCP (Model Context Protocol) server configurations, tool definitions, and agent manifests to map out every permission an AI agent has access to, then flags overly permissive or dangerous setups.

Think of it as `ls -la` for your AI agent's capabilities.

---

## Why This Exists

When you connect MCP servers to Claude Desktop, Cursor, Windsurf, or any MCP-compatible client, you're granting the AI agent real capabilities: filesystem access, shell execution, database queries, cloud resource management, browser automation, and more.

Most people don't fully understand what they've enabled. A single config file can give an AI agent the ability to read your SSH keys, send emails as you, query production databases, or execute arbitrary shell commands.

Agent Scope makes the invisible visible.

---

## Quick Start

```bash
# No dependencies — just Python 3.8+
python agent_scope.py              # GUI mode
python agent_scope.py --cli config.json    # CLI mode
python agent_scope.py --cli --auto-discover # Find configs automatically
```

---

## Features

### 🗺️ Permission Matrix
Visual map of every server × permission category — see at a glance which servers have filesystem, code execution, network, database, credential, cloud, or communication access.

### 🧠 Knowledge Base (43 MCP Servers)
Built-in intelligence for popular MCP server packages including their exact permission profiles. Unknown servers are flagged and analyzed heuristically.

**Recognized servers include:** filesystem, shell, PostgreSQL, MySQL, MongoDB, SQLite, Redis, GitHub, GitLab, Slack, Discord, email, Puppeteer, Playwright, Brave Search, Google Drive, Notion, AWS, GCP, Azure, Kubernetes, Docker, and more.

### ⚠️ Security Analysis
Automatic detection of:
- **Root filesystem access** — agent can read/write anything
- **Unrestricted shell execution** — full system compromise potential
- **Plaintext credentials** — database passwords and API tokens in config
- **Cloud infrastructure access** — resource creation, data exposure, billing risk
- **Multi-category permission combos** — excessive blast radius
- **Sensitive path exposure** — SSH keys, AWS credentials, home directory
- **Communication write access** — agent can send messages as you
- **Browser automation** — authenticated session risk
- **Unknown/unvetted servers** — capabilities can't be verified

### 📊 Export Formats
- **HTML** — Rich interactive report with permission matrix, server profiles, collapsible findings, severity filtering, and print styles
- **JSON** — Structured data for automation and SIEM integration

### 🖥️ Dual Mode
- **GUI** — Full Tkinter desktop app with dark theme, samples, and one-click auditing
- **CLI** — Terminal output with color coding, exit codes for CI/CD, and auto-discovery

### 🔍 Auto-Discovery
Automatically finds MCP configs on your system:
- Claude Desktop (`claude_desktop_config.json`)
- Cursor (`.cursor/mcp.json`)
- Project-level (`.mcp.json`, `mcp.json`)
- Windsurf / Codeium configs

---

## Permission Categories

| Icon | Category | What It Means |
|------|----------|---------------|
| 📁 | Filesystem | Read, write, delete, traverse files |
| 💻 | Code Execution | Shell commands, script execution |
| 🌐 | Network | HTTP requests, API calls |
| 🗄️ | Database | SQL queries, document stores |
| 🔑 | Credentials | Keys, tokens, passwords |
| 📧 | Communication | Email, Slack, Discord |
| ☁️ | Cloud | AWS, GCP, Azure resource management |
| 🔧 | System | Process management, OS commands |
| 🔍 | Browser | Web browsing, page interaction |
| 👤 | Identity | Auth, user data access |
| 💰 | Financial | Payment, billing systems |
| 💾 | Data | Memory, knowledge stores |

---

## CLI Usage

```bash
# Scan a specific config
python agent_scope.py --cli claude_desktop_config.json

# Auto-discover configs on your system
python agent_scope.py --cli --auto-discover

# Verbose output with descriptions and recommendations
python agent_scope.py --cli config.json --verbose

# Export as HTML report
python agent_scope.py --cli config.json --html -o report.html

# Export as JSON
python agent_scope.py --cli config.json --json -o report.json

# CI/CD usage (exit codes: 0=ok, 1=high, 2=critical)
python agent_scope.py --cli config.json || echo "Risky config detected!"
```

---

## Built-In Samples

Three pre-built configs for testing:

| Sample | Servers | Description |
|--------|---------|-------------|
| ✅ Minimal / Safe | 2 | Memory + search. Low risk. |
| 💀 Overly Permissive | 7 | Root filesystem, shell, prod DB with plaintext creds, AWS, browser, unknown server, Slack. Maximum attack surface. |
| ⚠️ Typical Developer | 4 | Scoped filesystem, GitHub, fetch, SQLite. Common setup with review-worthy items. |

---

## Risk Scoring

Findings are weighted by severity and capped at 100:

| Severity | Points | Examples |
|----------|--------|----------|
| CRITICAL | 25 | Root filesystem, shell exec |
| HIGH | 15 | Plaintext creds, cloud access |
| MEDIUM | 8 | Unknown server, browser, comms |
| LOW | 3 | Broad path access |
| INFO | 1 | Env var credentials (good practice) |

**Verdicts:** CLEAN (0) → LOW RISK (1-20) → MODERATE (21-50) → HIGH RISK (51-80) → CRITICAL (81-100)

---

## Use Cases

- **Developers** — Audit your Claude Desktop or Cursor config before adding new servers
- **Security Teams** — Validate MCP configurations across the organization
- **DevOps / SRE** — CI/CD gate to prevent overly permissive agent configs from deploying
- **Compliance** — Document AI agent access patterns for CMMC, SOC 2, or ISO 27001
- **Red Teams** — Map the attack surface exposed through AI agent integrations

---

## Requirements

- Python 3.8+
- No external dependencies
- Single file (`agent_scope.py`)
- GUI requires tkinter (included with most Python installations)

---

## Contributing

Contributions welcome — especially:
- **New MCP server profiles** for the knowledge base
- **Additional analysis rules** for emerging risk patterns
- **Config format support** for new MCP clients
- **Export formats** — SARIF, CSV, PDF

---

## License

MIT License — see [LICENSE](LICENSE)

---

## About NeatLabs™

**NeatLabs™** is a Service-Disabled Veteran-Owned Small Business (SDVOSB) specializing in cybersecurity, AI platform development, and federal compliance consulting.

Agent Scope is part of NeatLabs' security tooling portfolio, built to protect organizations operating in the AI agent ecosystem.

🌐 [neatlabs.ai](https://neatlabs.ai)
📧 [info@neatlabs.ai](mailto:info@neatlabs.ai)

---

*Built with 🔭 by NeatLabs™*
