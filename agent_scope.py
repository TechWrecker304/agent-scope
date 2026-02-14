#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                 NEATLABS™ AGENT SCOPE  v1.0                      ║
║            AI Agent Permission & Access Auditor                  ║
║                                                                  ║
║   Scan MCP server configs, tool definitions, and agent           ║
║   manifests to map what AI agents can access on your system      ║
║   and flag overly permissive or dangerous setups.                ║
║                                                                  ║
║   © 2025 NeatLabs™ — Service-Disabled Veteran-Owned Small Biz   ║
║   Released under the MIT License                                 ║
║   https://github.com/neatlabs/agent-scope                        ║
║   https://neatlabs.ai  •  info@neatlabs.ai                       ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    GUI Mode:   python agent_scope.py
    CLI Mode:   python agent_scope.py --cli config.json
    CLI Auto:   python agent_scope.py --cli --auto-discover
    CLI HTML:   python agent_scope.py --cli config.json --html -o report.html
"""

__version__ = "1.0.0"
__author__ = "NeatLabs™"
__license__ = "MIT"

import re
import os
import sys
import json
import glob
import hashlib
import argparse
import platform
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple, Any
from enum import Enum


# ═══════════════════════════════════════════════════════════════
# PERMISSION MODEL & DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class PermCategory(Enum):
    FILESYSTEM = "Filesystem"
    CODE_EXEC = "Code Execution"
    NETWORK = "Network"
    DATABASE = "Database"
    CREDENTIALS = "Credentials"
    COMMUNICATION = "Communication"
    CLOUD = "Cloud Services"
    SYSTEM = "System"
    BROWSER = "Browser"
    IDENTITY = "Identity & Auth"
    FINANCIAL = "Financial"
    DATA = "Data & Memory"

PERM_ICONS = {
    PermCategory.FILESYSTEM: "📁",
    PermCategory.CODE_EXEC: "💻",
    PermCategory.NETWORK: "🌐",
    PermCategory.DATABASE: "🗄️",
    PermCategory.CREDENTIALS: "🔑",
    PermCategory.COMMUNICATION: "📧",
    PermCategory.CLOUD: "☁️",
    PermCategory.SYSTEM: "🔧",
    PermCategory.BROWSER: "🔍",
    PermCategory.IDENTITY: "👤",
    PermCategory.FINANCIAL: "💰",
    PermCategory.DATA: "💾",
}

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 1,
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#FF1744",
    Severity.HIGH: "#FF6D00",
    Severity.MEDIUM: "#FFD600",
    Severity.LOW: "#00E5FF",
    Severity.INFO: "#B0BEC5",
}

SEVERITY_BG = {
    Severity.CRITICAL: "#3D0A0A",
    Severity.HIGH: "#3D2200",
    Severity.MEDIUM: "#3D3500",
    Severity.LOW: "#002A33",
    Severity.INFO: "#1A1F24",
}


@dataclass
class Permission:
    category: PermCategory
    action: str         # e.g. "read", "write", "execute", "admin"
    scope: str          # e.g. "/home/user", "*", "specific-db"
    description: str


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    category: str
    title: str
    description: str
    server_name: str
    recommendation: str
    detail: str = ""


@dataclass
class ServerProfile:
    name: str
    package: str
    command: str
    args: List[str]
    env: Dict[str, str]
    permissions: List[Permission] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    risk_label: str = "UNKNOWN"
    known: bool = False
    description: str = ""


@dataclass
class AuditReport:
    config_path: str
    config_type: str
    scan_time: str
    servers: List[ServerProfile] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    scan_duration_ms: float = 0.0
    engine_version: str = __version__

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def verdict(self) -> str:
        if self.risk_score == 0:
            return "CLEAN"
        elif self.risk_score <= 20:
            return "LOW RISK"
        elif self.risk_score <= 50:
            return "MODERATE"
        elif self.risk_score <= 80:
            return "HIGH RISK"
        return "CRITICAL"

    @property
    def total_permissions(self) -> int:
        return sum(len(s.permissions) for s in self.servers)

    @property
    def permission_categories(self) -> Set[PermCategory]:
        cats = set()
        for s in self.servers:
            for p in s.permissions:
                cats.add(p.category)
        return cats

    def to_dict(self) -> dict:
        return {
            "tool": f"NeatLabs Agent Scope v{self.engine_version}",
            "scan_time": self.scan_time,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "config": {"path": self.config_path, "type": self.config_type},
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "summary": {
                "servers": len(self.servers),
                "total_permissions": self.total_permissions,
                "permission_categories": len(self.permission_categories),
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "servers": [
                {
                    "name": s.name,
                    "package": s.package,
                    "known": s.known,
                    "risk": s.risk_label,
                    "permissions": [
                        {"category": p.category.value, "action": p.action,
                         "scope": p.scope, "description": p.description}
                        for p in s.permissions
                    ],
                    "findings": [
                        {"id": f.rule_id, "severity": f.severity.value,
                         "title": f.title, "description": f.description}
                        for f in s.findings
                    ],
                }
                for s in self.servers
            ],
            "findings": [
                {
                    "id": f.rule_id, "severity": f.severity.value,
                    "category": f.category, "title": f.title,
                    "description": f.description, "server": f.server_name,
                    "recommendation": f.recommendation, "detail": f.detail,
                }
                for f in self.findings
            ],
        }


# ═══════════════════════════════════════════════════════════════
# MCP SERVER KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════════

# Maps known MCP server packages to their capability profiles.
# This is the core intelligence — understanding what each server does.

MCP_KNOWLEDGE_BASE = {
    # ── Filesystem Servers ──
    "@modelcontextprotocol/server-filesystem": {
        "description": "Provides read/write access to local filesystem paths",
        "permissions": [
            (PermCategory.FILESYSTEM, "read", "configured paths", "Read files and directories"),
            (PermCategory.FILESYSTEM, "write", "configured paths", "Create and modify files"),
            (PermCategory.FILESYSTEM, "delete", "configured paths", "Delete files"),
            (PermCategory.FILESYSTEM, "traverse", "configured paths", "List directory contents"),
            (PermCategory.FILESYSTEM, "search", "configured paths", "Search files by pattern"),
        ],
        "risk_base": "MEDIUM",
        "args_are_paths": True,
    },
    "server-filesystem": {"_alias": "@modelcontextprotocol/server-filesystem"},
    "mcp-filesystem": {"_alias": "@modelcontextprotocol/server-filesystem"},

    # ── Code Execution Servers ──
    "@anthropic/mcp-server-shell": {
        "description": "Executes shell commands on the host system",
        "permissions": [
            (PermCategory.CODE_EXEC, "execute", "shell commands", "Run arbitrary shell commands"),
            (PermCategory.FILESYSTEM, "read", "entire system", "Shell can read any file"),
            (PermCategory.FILESYSTEM, "write", "entire system", "Shell can write any file"),
            (PermCategory.NETWORK, "outbound", "unrestricted", "Shell can make network calls"),
            (PermCategory.SYSTEM, "process", "all", "Can spawn/kill processes"),
        ],
        "risk_base": "CRITICAL",
    },
    "mcp-server-shell": {"_alias": "@anthropic/mcp-server-shell"},
    "@modelcontextprotocol/server-shell": {"_alias": "@anthropic/mcp-server-shell"},

    "mcp-server-exec": {
        "description": "Executes arbitrary commands or scripts",
        "permissions": [
            (PermCategory.CODE_EXEC, "execute", "arbitrary commands", "Run system commands"),
            (PermCategory.SYSTEM, "process", "spawned processes", "Process management"),
        ],
        "risk_base": "CRITICAL",
    },

    "@pydantic/mcp-run-python": {
        "description": "Executes Python code in a sandboxed environment",
        "permissions": [
            (PermCategory.CODE_EXEC, "execute", "Python code", "Run Python scripts"),
        ],
        "risk_base": "HIGH",
    },
    "mcp-run-python": {"_alias": "@pydantic/mcp-run-python"},

    # ── Database Servers ──
    "@modelcontextprotocol/server-postgres": {
        "description": "Provides SQL access to a PostgreSQL database",
        "permissions": [
            (PermCategory.DATABASE, "read", "PostgreSQL", "Execute SELECT queries"),
            (PermCategory.DATABASE, "write", "PostgreSQL", "Execute INSERT/UPDATE/DELETE"),
            (PermCategory.DATABASE, "schema", "PostgreSQL", "Read schema information"),
        ],
        "risk_base": "HIGH",
        "args_have_connstring": True,
    },
    "server-postgres": {"_alias": "@modelcontextprotocol/server-postgres"},
    "mcp-postgres": {"_alias": "@modelcontextprotocol/server-postgres"},

    "@modelcontextprotocol/server-sqlite": {
        "description": "Provides access to SQLite databases",
        "permissions": [
            (PermCategory.DATABASE, "read", "SQLite", "Query database"),
            (PermCategory.DATABASE, "write", "SQLite", "Modify database"),
            (PermCategory.FILESYSTEM, "read", "database file", "Access local db file"),
        ],
        "risk_base": "MEDIUM",
    },
    "server-sqlite": {"_alias": "@modelcontextprotocol/server-sqlite"},

    "mcp-server-mysql": {
        "description": "Provides SQL access to MySQL/MariaDB databases",
        "permissions": [
            (PermCategory.DATABASE, "read", "MySQL", "Execute SELECT queries"),
            (PermCategory.DATABASE, "write", "MySQL", "Execute modification queries"),
            (PermCategory.DATABASE, "schema", "MySQL", "Read schema information"),
        ],
        "risk_base": "HIGH",
        "args_have_connstring": True,
    },

    "mcp-server-mongo": {
        "description": "Provides access to MongoDB databases",
        "permissions": [
            (PermCategory.DATABASE, "read", "MongoDB", "Query collections"),
            (PermCategory.DATABASE, "write", "MongoDB", "Modify documents"),
            (PermCategory.DATABASE, "admin", "MongoDB", "Collection management"),
        ],
        "risk_base": "HIGH",
        "args_have_connstring": True,
    },

    # ── Network / Web Servers ──
    "@modelcontextprotocol/server-fetch": {
        "description": "Fetches content from URLs on the internet",
        "permissions": [
            (PermCategory.NETWORK, "outbound HTTP", "internet", "Fetch any URL"),
            (PermCategory.DATA, "read", "web content", "Read remote content"),
        ],
        "risk_base": "MEDIUM",
    },
    "server-fetch": {"_alias": "@modelcontextprotocol/server-fetch"},
    "mcp-fetch": {"_alias": "@modelcontextprotocol/server-fetch"},

    "@modelcontextprotocol/server-puppeteer": {
        "description": "Controls a headless Chrome browser",
        "permissions": [
            (PermCategory.BROWSER, "navigate", "any URL", "Browse any website"),
            (PermCategory.BROWSER, "interact", "page DOM", "Click, type, scrape"),
            (PermCategory.BROWSER, "screenshot", "pages", "Capture page screenshots"),
            (PermCategory.NETWORK, "outbound HTTP", "unrestricted", "Browser makes web requests"),
            (PermCategory.CODE_EXEC, "execute", "JavaScript", "Run JS in browser context"),
        ],
        "risk_base": "HIGH",
    },
    "server-puppeteer": {"_alias": "@modelcontextprotocol/server-puppeteer"},
    "mcp-puppeteer": {"_alias": "@modelcontextprotocol/server-puppeteer"},

    "@playwright/mcp": {
        "description": "Controls browsers via Playwright for web automation",
        "permissions": [
            (PermCategory.BROWSER, "navigate", "any URL", "Browse any website"),
            (PermCategory.BROWSER, "interact", "page DOM", "Click, type, fill forms"),
            (PermCategory.BROWSER, "screenshot", "pages", "Capture screenshots"),
            (PermCategory.NETWORK, "outbound HTTP", "unrestricted", "Browser HTTP requests"),
            (PermCategory.CODE_EXEC, "execute", "JavaScript", "Run JS in page context"),
        ],
        "risk_base": "HIGH",
    },

    # ── Communication Servers ──
    "@modelcontextprotocol/server-slack": {
        "description": "Interacts with Slack workspaces",
        "permissions": [
            (PermCategory.COMMUNICATION, "read", "Slack channels", "Read messages"),
            (PermCategory.COMMUNICATION, "write", "Slack channels", "Post messages"),
            (PermCategory.IDENTITY, "read", "Slack users", "Access user profiles"),
        ],
        "risk_base": "HIGH",
    },
    "server-slack": {"_alias": "@modelcontextprotocol/server-slack"},

    "mcp-server-discord": {
        "description": "Interacts with Discord servers",
        "permissions": [
            (PermCategory.COMMUNICATION, "read", "Discord channels", "Read messages"),
            (PermCategory.COMMUNICATION, "write", "Discord channels", "Send messages"),
        ],
        "risk_base": "MEDIUM",
    },

    "mcp-server-email": {
        "description": "Sends and reads emails",
        "permissions": [
            (PermCategory.COMMUNICATION, "read", "email inbox", "Read emails"),
            (PermCategory.COMMUNICATION, "write", "email", "Send emails"),
            (PermCategory.CREDENTIALS, "read", "SMTP/IMAP creds", "Email server credentials"),
        ],
        "risk_base": "HIGH",
    },

    # ── Cloud Service Servers ──
    "mcp-server-aws": {
        "description": "Interacts with AWS services",
        "permissions": [
            (PermCategory.CLOUD, "manage", "AWS resources", "AWS API access"),
            (PermCategory.CREDENTIALS, "use", "AWS credentials", "Uses IAM credentials"),
        ],
        "risk_base": "CRITICAL",
    },

    "@anthropic/mcp-server-gcp": {
        "description": "Interacts with Google Cloud Platform",
        "permissions": [
            (PermCategory.CLOUD, "manage", "GCP resources", "GCP API access"),
            (PermCategory.CREDENTIALS, "use", "GCP credentials", "Uses service account"),
        ],
        "risk_base": "CRITICAL",
    },

    "mcp-server-azure": {
        "description": "Interacts with Microsoft Azure",
        "permissions": [
            (PermCategory.CLOUD, "manage", "Azure resources", "Azure API access"),
            (PermCategory.CREDENTIALS, "use", "Azure credentials", "Uses Azure credentials"),
        ],
        "risk_base": "CRITICAL",
    },

    # ── Source Control ──
    "@modelcontextprotocol/server-github": {
        "description": "Interacts with GitHub API for repos, issues, PRs",
        "permissions": [
            (PermCategory.DATA, "read", "GitHub repos", "Read repo contents, issues, PRs"),
            (PermCategory.DATA, "write", "GitHub repos", "Create issues, PRs, comments"),
            (PermCategory.CREDENTIALS, "use", "GitHub token", "Uses PAT or OAuth token"),
        ],
        "risk_base": "MEDIUM",
    },
    "server-github": {"_alias": "@modelcontextprotocol/server-github"},

    "@modelcontextprotocol/server-gitlab": {
        "description": "Interacts with GitLab API",
        "permissions": [
            (PermCategory.DATA, "read", "GitLab repos", "Read repo contents"),
            (PermCategory.DATA, "write", "GitLab repos", "Create issues, MRs"),
            (PermCategory.CREDENTIALS, "use", "GitLab token", "Uses access token"),
        ],
        "risk_base": "MEDIUM",
    },

    # ── Memory / Data ──
    "@modelcontextprotocol/server-memory": {
        "description": "Provides persistent memory/knowledge graph storage",
        "permissions": [
            (PermCategory.DATA, "read", "memory store", "Read stored knowledge"),
            (PermCategory.DATA, "write", "memory store", "Write persistent data"),
        ],
        "risk_base": "LOW",
    },
    "server-memory": {"_alias": "@modelcontextprotocol/server-memory"},

    # ── Search ──
    "@modelcontextprotocol/server-brave-search": {
        "description": "Searches the web via Brave Search API",
        "permissions": [
            (PermCategory.NETWORK, "outbound HTTP", "Brave API", "Web search queries"),
            (PermCategory.DATA, "read", "search results", "Read search results"),
        ],
        "risk_base": "LOW",
    },
    "server-brave-search": {"_alias": "@modelcontextprotocol/server-brave-search"},

    "mcp-server-google-search": {
        "description": "Searches the web via Google",
        "permissions": [
            (PermCategory.NETWORK, "outbound HTTP", "Google API", "Web search queries"),
        ],
        "risk_base": "LOW",
    },

    # ── Productivity ──
    "@anthropic/mcp-server-google-drive": {
        "description": "Access Google Drive files",
        "permissions": [
            (PermCategory.FILESYSTEM, "read", "Google Drive", "Read files from Drive"),
            (PermCategory.FILESYSTEM, "write", "Google Drive", "Upload/modify Drive files"),
            (PermCategory.CREDENTIALS, "use", "Google OAuth", "Uses OAuth credentials"),
        ],
        "risk_base": "MEDIUM",
    },

    "mcp-server-notion": {
        "description": "Interacts with Notion workspaces",
        "permissions": [
            (PermCategory.DATA, "read", "Notion pages", "Read workspace content"),
            (PermCategory.DATA, "write", "Notion pages", "Create/edit pages"),
        ],
        "risk_base": "LOW",
    },

    # ── Monitoring ──
    "mcp-server-kubernetes": {
        "description": "Manages Kubernetes clusters",
        "permissions": [
            (PermCategory.CLOUD, "admin", "Kubernetes", "Full cluster management"),
            (PermCategory.SYSTEM, "process", "pods/containers", "Start/stop workloads"),
            (PermCategory.CREDENTIALS, "use", "kubeconfig", "Uses cluster credentials"),
        ],
        "risk_base": "CRITICAL",
    },

    "mcp-server-docker": {
        "description": "Manages Docker containers",
        "permissions": [
            (PermCategory.SYSTEM, "process", "Docker containers", "Start/stop containers"),
            (PermCategory.CODE_EXEC, "execute", "container commands", "Run commands in containers"),
            (PermCategory.NETWORK, "manage", "Docker networks", "Network configuration"),
        ],
        "risk_base": "CRITICAL",
    },

    # ── Everything / Dangerous ──
    "mcp-server-everything": {
        "description": "Meta-server providing access to multiple capabilities",
        "permissions": [
            (PermCategory.FILESYSTEM, "read", "broad", "File access"),
            (PermCategory.NETWORK, "outbound HTTP", "broad", "Network access"),
            (PermCategory.CODE_EXEC, "execute", "broad", "Code execution"),
        ],
        "risk_base": "CRITICAL",
    },
}

# Resolve aliases
for key in list(MCP_KNOWLEDGE_BASE.keys()):
    val = MCP_KNOWLEDGE_BASE[key]
    if "_alias" in val:
        target = val["_alias"]
        if target in MCP_KNOWLEDGE_BASE:
            MCP_KNOWLEDGE_BASE[key] = MCP_KNOWLEDGE_BASE[target].copy()


# ═══════════════════════════════════════════════════════════════
# ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════

class AgentScopeEngine:
    """Core engine that parses configs, profiles servers, and identifies risks."""

    def __init__(self):
        self.kb = MCP_KNOWLEDGE_BASE

    # ── Config Discovery ──

    def discover_configs(self) -> List[Tuple[str, str]]:
        """Find MCP config files on the system."""
        found = []
        system = platform.system()

        # Claude Desktop configs
        if system == "Darwin":
            p = Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
            if p.exists():
                found.append((str(p), "Claude Desktop"))
        elif system == "Windows":
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                p = Path(appdata) / "Claude" / "claude_desktop_config.json"
                if p.exists():
                    found.append((str(p), "Claude Desktop"))
        elif system == "Linux":
            p = Path.home() / ".config" / "claude" / "claude_desktop_config.json"
            if p.exists():
                found.append((str(p), "Claude Desktop"))

        # Project-level MCP configs
        cwd = Path.cwd()
        for name in [".mcp.json", "mcp.json", "mcp_config.json", ".cursor/mcp.json"]:
            p = cwd / name
            if p.exists():
                found.append((str(p), f"Project MCP ({name})"))

        # Walk up parent dirs for project configs
        for parent in cwd.parents:
            for name in [".mcp.json", "mcp.json"]:
                p = parent / name
                if p.exists():
                    found.append((str(p), f"Parent MCP ({p.name})"))
            if (parent / ".git").exists():
                break  # stop at repo root

        # Cursor configs
        cursor_dir = Path.home() / ".cursor"
        if cursor_dir.exists():
            for name in ["mcp.json", "mcp_config.json"]:
                p = cursor_dir / name
                if p.exists():
                    found.append((str(p), f"Cursor ({name})"))

        # Windsurf/Codeium
        for editor_dir in [".windsurf", ".codeium"]:
            p = Path.home() / editor_dir / "mcp_config.json"
            if p.exists():
                found.append((str(p), f"{editor_dir.strip('.')} MCP"))

        return found

    # ── Config Parsing ──

    def parse_config(self, filepath: str) -> Tuple[str, Dict]:
        """Parse a config file and return (config_type, parsed_dict)."""
        content = Path(filepath).read_text(encoding='utf-8', errors='replace')
        data = json.loads(content)

        # Detect config type
        if "mcpServers" in data:
            return "MCP (Claude Desktop / Cursor)", data
        elif "mcp" in data and "servers" in data.get("mcp", {}):
            # Some project configs nest under "mcp"
            return "MCP (Project)", {"mcpServers": data["mcp"]["servers"]}
        elif "servers" in data:
            return "MCP (Generic)", {"mcpServers": data["servers"]}
        elif "tools" in data or "actions" in data:
            return "OpenAI/GPT Actions", data
        else:
            # Try to interpret as MCP anyway
            return "Unknown (treating as MCP)", {"mcpServers": data}

    # ── Server Profiling ──

    def profile_server(self, name: str, config: Dict) -> ServerProfile:
        """Analyze a single MCP server config entry."""
        command = config.get("command", "")
        args = config.get("args", [])
        env = config.get("env", {})

        # Determine the package name
        package = self._identify_package(command, args)

        profile = ServerProfile(
            name=name,
            package=package,
            command=command,
            args=args,
            env=env,
        )

        # Check knowledge base
        kb_entry = self.kb.get(package)
        if kb_entry and "_alias" not in kb_entry:
            profile.known = True
            profile.description = kb_entry.get("description", "")
            profile.risk_label = kb_entry.get("risk_base", "UNKNOWN")

            # Add known permissions
            for perm_tuple in kb_entry.get("permissions", []):
                cat, action, scope, desc = perm_tuple
                # Refine scope based on actual args
                if kb_entry.get("args_are_paths") and args:
                    actual_paths = [a for a in args if a.startswith("/") or a.startswith("~") or a.startswith("C:")]
                    if actual_paths:
                        scope = ", ".join(actual_paths)
                profile.permissions.append(Permission(cat, action, scope, desc))
        else:
            profile.known = False
            profile.description = "Unknown server — not in knowledge base"
            profile.risk_label = "UNKNOWN"
            # Infer what we can from the package name
            self._infer_permissions(profile)

        # Run analysis rules
        self._analyze_server(profile)

        return profile

    def _identify_package(self, command: str, args: List[str]) -> str:
        """Extract the MCP server package name from command + args."""
        # npx -y @scope/server-name
        if command in ("npx", "npx.cmd"):
            for i, arg in enumerate(args):
                if arg.startswith("@") or arg.startswith("mcp-") or arg.startswith("server-"):
                    return arg
                if arg == "-y" or arg == "--yes":
                    continue
                if arg.startswith("-"):
                    continue
                # First non-flag arg is likely the package
                if not arg.startswith("-"):
                    return arg

        # node path/to/server.js
        if command in ("node", "node.exe"):
            for arg in args:
                if arg.endswith(".js") or arg.endswith(".mjs"):
                    return Path(arg).stem

        # python script.py
        if command in ("python", "python3", "python.exe"):
            for arg in args:
                if arg.endswith(".py"):
                    return Path(arg).stem
                if arg == "-m":
                    # next arg is module name
                    idx = args.index(arg)
                    if idx + 1 < len(args):
                        return args[idx + 1]

        # docker run image
        if command in ("docker", "docker.exe"):
            for i, arg in enumerate(args):
                if arg == "run" and i + 1 < len(args):
                    return args[-1]  # image name is usually last

        # uvx package
        if command in ("uvx", "uv"):
            for arg in args:
                if not arg.startswith("-"):
                    return arg

        # Direct executable
        return Path(command).stem if command else "unknown"

    def _infer_permissions(self, profile: ServerProfile):
        """Infer permissions for unknown servers based on name/args heuristics."""
        name_lower = (profile.package + " " + profile.name).lower()
        args_str = " ".join(profile.args).lower()

        # Filesystem hints
        if any(kw in name_lower for kw in ["file", "fs", "dir", "path", "folder"]):
            profile.permissions.append(Permission(PermCategory.FILESYSTEM, "inferred", "unknown scope", "Server name suggests filesystem access"))

        # Database hints
        if any(kw in name_lower for kw in ["sql", "postgres", "mysql", "mongo", "redis", "db", "database"]):
            profile.permissions.append(Permission(PermCategory.DATABASE, "inferred", "unknown scope", "Server name suggests database access"))

        # Network hints
        if any(kw in name_lower for kw in ["fetch", "http", "api", "web", "request", "url"]):
            profile.permissions.append(Permission(PermCategory.NETWORK, "inferred", "unknown scope", "Server name suggests network access"))

        # Code execution hints
        if any(kw in name_lower for kw in ["shell", "exec", "run", "command", "bash", "terminal"]):
            profile.permissions.append(Permission(PermCategory.CODE_EXEC, "inferred", "unknown scope", "Server name suggests code execution"))

        # Browser hints
        if any(kw in name_lower for kw in ["browser", "puppeteer", "playwright", "chrome", "selenium"]):
            profile.permissions.append(Permission(PermCategory.BROWSER, "inferred", "unknown scope", "Server name suggests browser control"))

        # Cloud hints
        if any(kw in name_lower for kw in ["aws", "gcp", "azure", "cloud", "s3", "lambda"]):
            profile.permissions.append(Permission(PermCategory.CLOUD, "inferred", "unknown scope", "Server name suggests cloud access"))

        # Check for paths in args
        for arg in profile.args:
            if arg.startswith("/") or arg.startswith("~") or (len(arg) > 2 and arg[1] == ":"):
                profile.permissions.append(Permission(PermCategory.FILESYSTEM, "path access", arg, f"Path argument: {arg}"))

        # Check for connection strings in args
        for arg in profile.args:
            if re.match(r'(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://', arg, re.I):
                profile.permissions.append(Permission(PermCategory.DATABASE, "connection", "via connection string", "Connection string in arguments"))
                profile.permissions.append(Permission(PermCategory.CREDENTIALS, "exposed", "in plaintext args", "Credentials visible in config"))

    # ── Analysis Rules ──

    def _analyze_server(self, profile: ServerProfile):
        """Run security analysis rules against a server profile."""
        name = profile.name
        findings = profile.findings

        # RULE: Unrestricted shell access
        if any(p.category == PermCategory.CODE_EXEC and p.action == "execute" for p in profile.permissions):
            if any("shell" in (profile.package + profile.command).lower() for _ in [1]):
                findings.append(Finding(
                    "PERM-001", Severity.CRITICAL, "Overly Permissive",
                    "Unrestricted Shell Execution",
                    "This server can execute arbitrary shell commands on the host system. An AI agent with this access can read/write any file, install software, exfiltrate data, or compromise the entire machine.",
                    name, "Remove shell access or replace with a scoped tool that only allows specific, whitelisted commands.",
                ))

        # RULE: Credentials in plaintext args
        for arg in profile.args:
            if re.match(r'(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:]+:.+@', arg, re.I):
                findings.append(Finding(
                    "CRED-001", Severity.HIGH, "Credential Exposure",
                    "Database Credentials in Plaintext",
                    f"Connection string with embedded password found in config arguments. Anyone with access to this config file can read the database credentials.",
                    name, "Use environment variables for credentials instead of embedding them in the config.",
                    detail=re.sub(r'://([^:]+):([^@]+)@', r'://\1:****@', arg),
                ))
            if re.match(r'(?:sk-|ghp_|gho_|glpat-|xoxb-|xoxp-)', arg):
                findings.append(Finding(
                    "CRED-002", Severity.HIGH, "Credential Exposure",
                    "API Token in Plaintext Arguments",
                    "An API token or key is directly visible in the server arguments.",
                    name, "Move tokens to environment variables or a secrets manager.",
                ))

        # RULE: Credentials in env vars (good practice, but note them)
        sensitive_env_keys = [k for k in profile.env.keys()
                             if any(w in k.upper() for w in ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASS", "CRED", "AUTH"])]
        if sensitive_env_keys:
            vals_redacted = ", ".join(sensitive_env_keys)
            findings.append(Finding(
                "CRED-003", Severity.INFO, "Credential Management",
                "Credentials Passed via Environment",
                f"Sensitive-looking environment variables configured: {vals_redacted}. This is better than plaintext args, but verify the config file itself is protected.",
                name, "Ensure the config file has restricted permissions (chmod 600). Consider using a secrets manager.",
            ))

        # RULE: Sensitive filesystem paths
        sensitive_paths = ["/", "/etc", "/root", "/var", "/usr"]
        home_ssh = str(Path.home() / ".ssh")
        home_aws = str(Path.home() / ".aws")
        sensitive_paths.extend([home_ssh, home_aws, str(Path.home())])

        for arg in profile.args:
            if arg in ("/", "C:\\"):
                findings.append(Finding(
                    "PATH-001", Severity.CRITICAL, "Overly Permissive",
                    "Root Filesystem Access",
                    "Server is configured with access to the root of the filesystem. The AI agent can read and potentially modify ANY file on the system.",
                    name, "Restrict to specific directories the agent actually needs. Use the most narrow path possible.",
                ))
            elif arg in sensitive_paths or any(arg.startswith(sp + "/") for sp in ["/etc", "/root", home_ssh, home_aws]):
                findings.append(Finding(
                    "PATH-002", Severity.HIGH, "Sensitive Path Access",
                    f"Access to Sensitive Path: {arg}",
                    f"Server has access to '{arg}', which may contain credentials, keys, or system configuration.",
                    name, f"Remove access to '{arg}' unless absolutely required. Scope to a specific subdirectory.",
                ))

        # RULE: Home directory access (broad)
        home = str(Path.home())
        for arg in profile.args:
            if arg == home or arg == "~":
                findings.append(Finding(
                    "PATH-003", Severity.MEDIUM, "Broad Access",
                    "Entire Home Directory Exposed",
                    "Server has access to the user's entire home directory, which likely contains SSH keys, cloud credentials, browser data, and other sensitive files.",
                    name, "Restrict to specific subdirectories (e.g., ~/Projects/specific-project).",
                ))

        # RULE: Cloud service access
        if any(p.category == PermCategory.CLOUD for p in profile.permissions):
            findings.append(Finding(
                "CLOUD-001", Severity.HIGH, "Cloud Access",
                "Cloud Infrastructure Access",
                "This server can interact with cloud infrastructure. Misconfiguration could lead to resource creation, data exposure, or billing charges.",
                name, "Use least-privilege IAM roles. Restrict to read-only where possible. Monitor cloud audit logs.",
            ))

        # RULE: Communication access (can send messages as the user)
        if any(p.category == PermCategory.COMMUNICATION and p.action == "write" for p in profile.permissions):
            findings.append(Finding(
                "COMM-001", Severity.MEDIUM, "Communication Access",
                "Can Send Messages as User",
                "This server can send messages (email, Slack, Discord) on behalf of the user. A compromised or manipulated agent could send phishing messages or leak information.",
                name, "Enable message approval workflows. Restrict to specific channels/recipients where possible.",
            ))

        # RULE: Browser access
        if any(p.category == PermCategory.BROWSER for p in profile.permissions):
            findings.append(Finding(
                "BROWSER-001", Severity.MEDIUM, "Browser Access",
                "Browser Automation Capabilities",
                "This server controls a web browser. It can navigate to any URL, interact with pages, and potentially access authenticated sessions if cookies persist.",
                name, "Use a dedicated browser profile with no saved credentials. Consider network-level URL filtering.",
            ))

        # RULE: Unknown server (not in knowledge base)
        if not profile.known:
            findings.append(Finding(
                "UNK-001", Severity.MEDIUM, "Unknown Server",
                f"Unrecognized Server: {profile.package}",
                "This server is not in the Agent Scope knowledge base. Its permissions and capabilities cannot be automatically assessed.",
                name, "Manually review the server's documentation and source code to understand what access it requires.",
            ))

        # RULE: Multiple high-risk categories
        high_risk_cats = {p.category for p in profile.permissions
                         if p.category in (PermCategory.CODE_EXEC, PermCategory.FILESYSTEM, PermCategory.DATABASE, PermCategory.CLOUD)}
        if len(high_risk_cats) >= 3:
            findings.append(Finding(
                "COMBO-001", Severity.HIGH, "Excessive Permissions",
                "Multi-Category High-Risk Access",
                f"This server has access across {len(high_risk_cats)} high-risk categories: {', '.join(c.value for c in high_risk_cats)}. The combination greatly increases blast radius if compromised.",
                name, "Apply principle of least privilege. Consider splitting into multiple narrowly-scoped servers.",
            ))

        # RULE: No environment isolation
        if profile.command in ("npx", "npx.cmd", "node", "python", "python3"):
            if not profile.env.get("NODE_ENV") and not any("sandbox" in a.lower() for a in profile.args):
                pass  # Info-level, don't spam

        # Update risk label based on findings
        if any(f.severity == Severity.CRITICAL for f in findings):
            profile.risk_label = "CRITICAL"
        elif any(f.severity == Severity.HIGH for f in findings):
            profile.risk_label = max(profile.risk_label, "HIGH") if profile.risk_label != "CRITICAL" else profile.risk_label

    # ── Main Audit ──

    def audit(self, filepath: str) -> AuditReport:
        """Run a full audit on a config file."""
        import time
        t0 = time.perf_counter()

        config_type, data = self.parse_config(filepath)
        servers_data = data.get("mcpServers", {})

        report = AuditReport(
            config_path=filepath,
            config_type=config_type,
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        for name, config in servers_data.items():
            profile = self.profile_server(name, config)
            report.servers.append(profile)
            report.findings.extend(profile.findings)

        # Sort findings by severity
        report.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])

        # Risk score
        raw = sum(SEVERITY_WEIGHTS[f.severity] for f in report.findings)
        report.risk_score = min(100.0, raw)
        report.scan_duration_ms = (time.perf_counter() - t0) * 1000

        return report


# ═══════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════

def _h(text: str) -> str:
    """HTML escape."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def generate_html_report(report: AuditReport) -> str:
    score = report.risk_score
    if score == 0:
        vc, vbg = "#00E676", "#0a2e1a"
    elif score <= 20:
        vc, vbg = "#00E5FF", "#0a1e2e"
    elif score <= 50:
        vc, vbg = "#FFD600", "#2e2a0a"
    elif score <= 80:
        vc, vbg = "#FF6D00", "#2e1a0a"
    else:
        vc, vbg = "#FF1744", "#2e0a0a"

    # Permission matrix HTML
    all_cats = set()
    for s in report.servers:
        for p in s.permissions:
            all_cats.add(p.category)
    cat_list = sorted(all_cats, key=lambda c: c.value)

    matrix_rows = ""
    for s in report.servers:
        server_cats = {p.category for p in s.permissions}
        risk_class = s.risk_label.lower() if s.risk_label in ("CRITICAL","HIGH","MEDIUM","LOW") else "unknown"
        cells = ""
        for cat in cat_list:
            if cat in server_cats:
                actions = set(p.action for p in s.permissions if p.category == cat)
                tip = ", ".join(actions)
                cells += f'<td class="perm-yes" title="{_h(tip)}">●</td>'
            else:
                cells += '<td class="perm-no">—</td>'
        matrix_rows += f'<tr><td class="server-name"><span class="risk-dot risk-{risk_class}">●</span> {_h(s.name)}</td>{cells}</tr>\n'

    matrix_headers = "".join(f'<th class="cat-header"><span class="cat-icon">{PERM_ICONS.get(c,"")}</span><br>{_h(c.value)}</th>' for c in cat_list)

    # Server cards HTML
    server_cards = ""
    for i, s in enumerate(report.servers):
        risk_class = s.risk_label.lower() if s.risk_label in ("CRITICAL","HIGH","MEDIUM","LOW") else "unknown"
        known_badge = '<span class="badge known">✓ Known</span>' if s.known else '<span class="badge unknown">? Unknown</span>'
        risk_badge = f'<span class="badge risk-badge-{risk_class}">{s.risk_label}</span>'

        perms_html = ""
        for p in s.permissions:
            perms_html += f'<div class="perm-item"><span class="perm-icon">{PERM_ICONS.get(p.category, "")}</span><span class="perm-cat">{_h(p.category.value)}</span><span class="perm-action">{_h(p.action)}</span><span class="perm-scope">{_h(p.scope)}</span></div>'

        findings_html = ""
        for f in s.findings:
            sev_cls = f.severity.value.lower()
            findings_html += f'<div class="srv-finding finding-{sev_cls}"><span class="severity-badge badge-{sev_cls}">{f.severity.value}</span><span class="srv-finding-title">{_h(f.title)}</span><p class="srv-finding-desc">{_h(f.description)}</p><p class="srv-finding-rec">💡 {_h(f.recommendation)}</p></div>'

        env_html = ""
        if s.env:
            env_items = ", ".join(f'<code>{_h(k)}</code>' for k in s.env.keys())
            env_html = f'<div class="srv-env"><strong>Environment:</strong> {env_items}</div>'

        server_cards += f"""
        <div class="server-card" id="server-{i}">
            <div class="srv-header" onclick="toggleServer({i})">
                <div class="srv-left">
                    <span class="risk-dot risk-{risk_class}">●</span>
                    <span class="srv-name">{_h(s.name)}</span>
                    {risk_badge} {known_badge}
                </div>
                <div class="srv-right">
                    <span class="srv-perms-count">{len(s.permissions)} perms</span>
                    <span class="srv-findings-count">{len(s.findings)} findings</span>
                    <span class="chevron" id="srv-chev-{i}">▸</span>
                </div>
            </div>
            <div class="srv-body" id="srv-body-{i}">
                <div class="srv-meta">
                    <div class="srv-detail"><strong>Package:</strong> <code>{_h(s.package)}</code></div>
                    <div class="srv-detail"><strong>Command:</strong> <code>{_h(s.command)} {_h(' '.join(s.args[:5]))}</code></div>
                    <div class="srv-detail"><strong>Description:</strong> {_h(s.description)}</div>
                    {env_html}
                </div>
                <div class="srv-perms-section">
                    <h4>Permissions ({len(s.permissions)})</h4>
                    <div class="perms-grid">{perms_html}</div>
                </div>
                <div class="srv-findings-section">
                    <h4>Findings ({len(s.findings)})</h4>
                    {findings_html if findings_html else '<p class="dim">No issues found for this server.</p>'}
                </div>
            </div>
        </div>"""

    # All findings HTML
    all_findings_html = ""
    for i, f in enumerate(report.findings):
        sev_cls = f.severity.value.lower()
        all_findings_html += f"""
        <div class="finding-row finding-{sev_cls}">
            <span class="severity-badge badge-{sev_cls}">{f.severity.value}</span>
            <span class="finding-server">{_h(f.server_name)}</span>
            <span class="finding-title-text">{_h(f.title)}</span>
            <div class="finding-detail-text">{_h(f.description)}</div>
            <div class="finding-rec-text">💡 {_h(f.recommendation)}</div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Agent Scope Report — {_h(Path(report.config_path).name)}</title>
<style>
:root {{
    --bg: #0D1117; --panel: #161B22; --card: #1C2333; --hover: #242D3D;
    --fg: #E6EDF3; --fg2: #8B949E; --dim: #484F58; --accent: #00D4AA;
    --accent2: #58A6FF; --border: #30363D; --radius: 8px;
    --critical: #FF1744; --high: #FF6D00; --medium: #FFD600; --low: #00E5FF; --info: #78909C;
    --crit-bg: #2D0A0A; --high-bg: #2D1A00; --med-bg: #2D2800; --low-bg: #00202E; --info-bg: #1A1F24;
}}
*,*::before,*::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif; background: var(--bg); color: var(--fg); line-height: 1.6; }}
a {{ color: var(--accent2); text-decoration: none; }}
code {{ font-family: 'Consolas','Courier New',monospace; font-size: 0.9em; background: #000; padding: 2px 6px; border-radius: 3px; }}

.topbar {{ background: var(--panel); border-bottom: 2px solid var(--accent); padding: 20px 40px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }}
.logo {{ display: flex; align-items: center; gap: 14px; }}
.logo h1 {{ font-family: 'Consolas',monospace; font-size: 20px; color: var(--accent); }}
.logo p {{ font-family: 'Consolas',monospace; font-size: 11px; color: var(--fg2); }}
.verdict-chip {{ font-family: 'Consolas',monospace; font-size: 14px; font-weight: bold; color: {vc}; background: {vbg}; padding: 6px 18px; border-radius: 20px; border: 1px solid {vc}44; }}
.print-btn {{ background: var(--card); color: var(--fg2); border: 1px solid var(--border); padding: 6px 16px; border-radius: var(--radius); cursor: pointer; font-size: 13px; }}
.print-btn:hover {{ background: var(--accent); color: var(--bg); }}

.container {{ max-width: 1200px; margin: 0 auto; padding: 30px 40px 60px; }}
h2 {{ font-family: 'Consolas',monospace; color: var(--accent); font-size: 16px; margin: 30px 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}

/* Summary Grid */
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap: 12px; margin-bottom: 30px; }}
.sum-card {{ background: var(--panel); border-radius: var(--radius); padding: 18px; border: 1px solid var(--border); text-align: center; }}
.sum-card .val {{ font-family: 'Consolas',monospace; font-size: 28px; font-weight: bold; color: var(--accent); }}
.sum-card .lbl {{ font-size: 11px; color: var(--fg2); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}

/* Severity Counters */
.sev-bar {{ display: grid; grid-template-columns: repeat(5,1fr); gap: 8px; margin-bottom: 30px; }}
.sev-c {{ border-radius: var(--radius); padding: 14px; text-align: center; }}
.sev-c.critical {{ background: var(--crit-bg); }} .sev-c.high {{ background: var(--high-bg); }}
.sev-c.medium {{ background: var(--med-bg); }} .sev-c.low {{ background: var(--low-bg); }}
.sev-c.info {{ background: var(--info-bg); }}
.sev-c .n {{ font-family: 'Consolas',monospace; font-size: 26px; font-weight: bold; }}
.sev-c .l {{ font-family: 'Consolas',monospace; font-size: 10px; font-weight: bold; letter-spacing: 1px; }}
.sev-c.critical .n,.sev-c.critical .l {{ color: var(--critical); }}
.sev-c.high .n,.sev-c.high .l {{ color: var(--high); }}
.sev-c.medium .n,.sev-c.medium .l {{ color: var(--medium); }}
.sev-c.low .n,.sev-c.low .l {{ color: var(--low); }}
.sev-c.info .n,.sev-c.info .l {{ color: var(--info); }}

/* Permission Matrix */
.matrix-wrap {{ overflow-x: auto; margin-bottom: 30px; }}
.matrix {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
.matrix th {{ padding: 10px 8px; background: var(--panel); color: var(--fg2); font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }}
.matrix td {{ padding: 10px 8px; text-align: center; border-bottom: 1px solid var(--border)66; }}
.matrix .server-name {{ text-align: left; font-weight: 600; font-size: 13px; white-space: nowrap; }}
.matrix .cat-header {{ text-align: center; min-width: 70px; }}
.cat-icon {{ font-size: 16px; }}
.perm-yes {{ color: var(--accent); font-size: 16px; }}
.perm-no {{ color: var(--dim); }}
.matrix tr:hover {{ background: var(--hover); }}

.risk-dot {{ font-size: 14px; }}
.risk-critical {{ color: var(--critical); }}
.risk-high {{ color: var(--high); }}
.risk-medium {{ color: var(--medium); }}
.risk-low {{ color: var(--low); }}
.risk-unknown {{ color: var(--fg2); }}

/* Server Cards */
.server-card {{ background: var(--panel); border-radius: var(--radius); margin-bottom: 10px; border: 1px solid var(--border); overflow: hidden; }}
.srv-header {{ padding: 14px 20px; display: flex; align-items: center; justify-content: space-between; cursor: pointer; }}
.srv-header:hover {{ background: var(--hover); }}
.srv-left {{ display: flex; align-items: center; gap: 10px; }}
.srv-right {{ display: flex; align-items: center; gap: 14px; font-size: 12px; color: var(--fg2); }}
.srv-name {{ font-weight: 700; font-size: 14px; }}
.badge {{ font-size: 10px; font-weight: bold; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
.badge.known {{ background: #0a2e1a; color: #00E676; }}
.badge.unknown {{ background: #2e2a0a; color: #FFD600; }}
.risk-badge-critical {{ background: var(--crit-bg); color: var(--critical); }}
.risk-badge-high {{ background: var(--high-bg); color: var(--high); }}
.risk-badge-medium {{ background: var(--med-bg); color: var(--medium); }}
.risk-badge-low {{ background: var(--low-bg); color: var(--low); }}
.risk-badge-unknown {{ background: var(--info-bg); color: var(--fg2); }}
.chevron {{ color: var(--dim); transition: transform 0.2s; }}
.srv-body {{ display: none; padding: 0 20px 20px; }}
.srv-body.open {{ display: block; }}
.srv-meta {{ background: var(--card); border-radius: 6px; padding: 14px; margin-bottom: 14px; }}
.srv-detail {{ font-size: 13px; margin-bottom: 4px; }}
.srv-detail strong {{ color: var(--accent); }}

.perms-grid {{ display: grid; grid-template-columns: repeat(auto-fill,minmax(280px,1fr)); gap: 6px; margin-top: 8px; }}
.perm-item {{ display: flex; align-items: center; gap: 8px; font-size: 12px; padding: 6px 10px; background: var(--card); border-radius: 4px; }}
.perm-icon {{ font-size: 14px; }}
.perm-cat {{ font-weight: 600; color: var(--accent); min-width: 100px; }}
.perm-action {{ color: var(--fg); }}
.perm-scope {{ color: var(--fg2); font-family: 'Consolas',monospace; font-size: 11px; }}

.srv-finding {{ padding: 10px 14px; border-radius: 6px; margin-bottom: 8px; border-left: 3px solid var(--border); }}
.srv-finding.finding-critical {{ background: var(--crit-bg); border-left-color: var(--critical); }}
.srv-finding.finding-high {{ background: var(--high-bg); border-left-color: var(--high); }}
.srv-finding.finding-medium {{ background: var(--med-bg); border-left-color: var(--medium); }}
.srv-finding.finding-low {{ background: var(--low-bg); border-left-color: var(--low); }}
.srv-finding.finding-info {{ background: var(--info-bg); border-left-color: var(--info); }}
.srv-finding-title {{ font-weight: 600; margin-left: 8px; }}
.srv-finding-desc {{ font-size: 12px; color: var(--fg2); margin: 6px 0; }}
.srv-finding-rec {{ font-size: 12px; color: var(--accent); }}
.severity-badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-family: 'Consolas',monospace; font-size: 9px; font-weight: bold; color: #fff; }}
.badge-critical {{ background: var(--critical); }} .badge-high {{ background: var(--high); }}
.badge-medium {{ background: var(--medium); color: #000; }} .badge-low {{ background: var(--low); color: #000; }}
.badge-info {{ background: var(--info); color: #000; }}

/* All Findings */
.finding-row {{ padding: 12px 16px; border-radius: 6px; margin-bottom: 6px; border-left: 3px solid var(--border); }}
.finding-row.finding-critical {{ background: var(--crit-bg); border-left-color: var(--critical); }}
.finding-row.finding-high {{ background: var(--high-bg); border-left-color: var(--high); }}
.finding-row.finding-medium {{ background: var(--med-bg); border-left-color: var(--medium); }}
.finding-row.finding-low {{ background: var(--low-bg); border-left-color: var(--low); }}
.finding-row.finding-info {{ background: var(--info-bg); border-left-color: var(--info); }}
.finding-server {{ font-family: 'Consolas',monospace; font-size: 11px; color: var(--fg2); margin: 0 8px; }}
.finding-title-text {{ font-weight: 600; }}
.finding-detail-text {{ font-size: 12px; color: var(--fg2); margin: 6px 0 4px; }}
.finding-rec-text {{ font-size: 12px; color: var(--accent); }}

.dim {{ color: var(--dim); }}
.footer {{ text-align: center; padding: 30px; color: var(--dim); font-size: 12px; border-top: 1px solid var(--border); margin-top: 40px; }}
.footer a {{ color: var(--accent); }}

@media print {{
    body {{ background: #fff !important; color: #000 !important; }}
    .topbar {{ position: relative; background: #fff !important; box-shadow: none; border-bottom: 2px solid #000; }}
    .logo h1 {{ color: #000 !important; }}
    .print-btn {{ display: none; }}
    .srv-body {{ display: block !important; }}
    .server-card,.finding-row {{ break-inside: avoid; box-shadow: none; }}
}}
</style>
</head>
<body>
<div class="topbar">
    <div class="logo"><span style="font-size:32px">🔭</span><div><h1>NEATLABS™ AGENT SCOPE</h1><p>AI Agent Permission &amp; Access Auditor &nbsp;•&nbsp; v{__version__}</p></div></div>
    <div style="display:flex;align-items:center;gap:16px"><span class="verdict-chip">{report.verdict} — {score:.0f}/100</span><button class="print-btn" onclick="window.print()">🖨️ Print</button></div>
</div>
<div class="container">

<div class="summary-grid">
    <div class="sum-card"><div class="val">{len(report.servers)}</div><div class="lbl">MCP Servers</div></div>
    <div class="sum-card"><div class="val">{report.total_permissions}</div><div class="lbl">Permissions</div></div>
    <div class="sum-card"><div class="val">{len(report.permission_categories)}</div><div class="lbl">Access Categories</div></div>
    <div class="sum-card"><div class="val">{len(report.findings)}</div><div class="lbl">Findings</div></div>
    <div class="sum-card"><div class="val" style="color:{vc}">{score:.0f}</div><div class="lbl">Risk Score</div></div>
    <div class="sum-card"><div class="val">{report.scan_duration_ms:.1f}<span style="font-size:12px;color:var(--dim)">ms</span></div><div class="lbl">Scan Time</div></div>
</div>

<div class="sev-bar">
    <div class="sev-c critical"><div class="n">{report.critical_count}</div><div class="l">Critical</div></div>
    <div class="sev-c high"><div class="n">{report.high_count}</div><div class="l">High</div></div>
    <div class="sev-c medium"><div class="n">{report.medium_count}</div><div class="l">Medium</div></div>
    <div class="sev-c low"><div class="n">{report.low_count}</div><div class="l">Low</div></div>
    <div class="sev-c info"><div class="n">{report.info_count}</div><div class="l">Info</div></div>
</div>

<h2>🗺️ Permission Matrix</h2>
<div class="matrix-wrap"><table class="matrix">
<thead><tr><th style="text-align:left">Server</th>{matrix_headers}</tr></thead>
<tbody>{matrix_rows}</tbody>
</table></div>

<h2>🔭 Server Profiles ({len(report.servers)})</h2>
{server_cards}

<h2>⚠️ All Findings ({len(report.findings)})</h2>
{all_findings_html if all_findings_html else '<p class="dim">No security findings. Configuration looks good.</p>'}

</div>
<div class="footer">
    <p>Generated by <strong>NeatLabs™ Agent Scope</strong> v{__version__} &nbsp;•&nbsp; {report.scan_time}</p>
    <p><a href="https://github.com/neatlabs/agent-scope">github.com/neatlabs/agent-scope</a> &nbsp;•&nbsp; <a href="https://neatlabs.ai">neatlabs.ai</a> &nbsp;•&nbsp; MIT License</p>
    <p style="margin-top:8px;font-size:11px">© {datetime.now().year} NeatLabs™ — Service-Disabled Veteran-Owned Small Business &nbsp;•&nbsp; info@neatlabs.ai</p>
</div>
<script>
function toggleServer(i) {{
    const b = document.getElementById('srv-body-'+i);
    const c = document.getElementById('srv-chev-'+i);
    if (b.classList.contains('open')) {{ b.classList.remove('open'); c.textContent='▸'; }}
    else {{ b.classList.add('open'); c.textContent='▾'; }}
}}
</script>
</body></html>"""


# ═══════════════════════════════════════════════════════════════
# SAMPLE CONFIGS FOR TESTING
# ═══════════════════════════════════════════════════════════════

SAMPLE_SAFE = {
    "mcpServers": {
        "memory": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory"]
        },
        "brave-search": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-brave-search"],
            "env": {"BRAVE_API_KEY": "BSA..."}
        }
    }
}

SAMPLE_RISKY = {
    "mcpServers": {
        "filesystem-everything": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
        },
        "shell": {
            "command": "npx",
            "args": ["-y", "@anthropic/mcp-server-shell"]
        },
        "postgres-prod": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-postgres",
                     "postgresql://admin:SuperSecret123@prod-db.company.com:5432/production"]
        },
        "puppeteer": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-puppeteer"]
        },
        "aws-manager": {
            "command": "npx",
            "args": ["-y", "mcp-server-aws"],
            "env": {"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secret"}
        },
        "mystery-server": {
            "command": "node",
            "args": ["/opt/custom/my-agent-tools.js", "--unrestricted"]
        },
        "slack": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-slack"],
            "env": {"SLACK_BOT_TOKEN": "xoxb-..."}
        }
    }
}

SAMPLE_TYPICAL = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem",
                     str(Path.home() / "Projects")]
        },
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..."}
        },
        "fetch": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-fetch"]
        },
        "sqlite": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-sqlite", "./data/app.db"]
        }
    }
}


# ═══════════════════════════════════════════════════════════════
# CLI MODE
# ═══════════════════════════════════════════════════════════════

class CLIRunner:
    SEVERITY_SYM = {
        Severity.CRITICAL: "\033[91m█ CRITICAL\033[0m",
        Severity.HIGH:     "\033[93m▓ HIGH    \033[0m",
        Severity.MEDIUM:   "\033[33m▒ MEDIUM  \033[0m",
        Severity.LOW:      "\033[96m░ LOW     \033[0m",
        Severity.INFO:     "\033[37m· INFO    \033[0m",
    }

    def run(self, args):
        engine = AgentScopeEngine()

        if args.auto_discover:
            configs = engine.discover_configs()
            if not configs:
                print("\033[93mNo MCP configs found automatically.\033[0m")
                print("Try specifying a config path: agent_scope.py --cli path/to/config.json")
                return 1
            print(f"\033[1;36mDiscovered {len(configs)} config(s):\033[0m")
            for path, desc in configs:
                print(f"  {desc}: {path}")
            filepath = configs[0][0]
        else:
            filepath = args.target
            if not Path(filepath).exists():
                print(f"\033[91mFile not found: {filepath}\033[0m")
                return 1

        report = engine.audit(filepath)

        if args.json:
            out = json.dumps(report.to_dict(), indent=2)
            if args.output:
                Path(args.output).write_text(out)
                print(f"JSON report saved to {args.output}")
            else:
                print(out)
        elif args.html:
            html = generate_html_report(report)
            outpath = args.output or f"agent-scope-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
            Path(outpath).write_text(html)
            print(f"HTML report saved to {outpath}")
        else:
            self._print_report(report, args.verbose)

        if report.critical_count:
            return 2
        elif report.high_count:
            return 1
        return 0

    def _print_report(self, report, verbose):
        score = report.risk_score
        if score == 0: sc = f"\033[92m{score:.0f}\033[0m"
        elif score <= 20: sc = f"\033[96m{score:.0f}\033[0m"
        elif score <= 50: sc = f"\033[93m{score:.0f}\033[0m"
        else: sc = f"\033[91;1m{score:.0f}\033[0m"

        print(f"\n\033[1m{'═'*60}\033[0m")
        print(f"  \033[1;36mNEATLABS™ AGENT SCOPE\033[0m — AI Agent Permission Auditor")
        print(f"  Config: {report.config_path}")
        print(f"  Score: {sc}/100 ({report.verdict}) | {len(report.servers)} servers | {len(report.findings)} findings")
        print(f"\033[1m{'═'*60}\033[0m")

        # Permission matrix
        print(f"\n  \033[1;36m🗺️  Permission Matrix\033[0m")
        for s in report.servers:
            cats = sorted(set(p.category.value for p in s.permissions))
            risk_colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m", "LOW": "\033[96m"}
            rc = risk_colors.get(s.risk_label, "\033[37m")
            known = "✓" if s.known else "?"
            cats_str = ", ".join(cats) if cats else "none identified"
            print(f"  {rc}● {s.risk_label:8s}\033[0m  [{known}] {s.name:20s}  → {cats_str}")

        # Findings
        if report.findings:
            print(f"\n  \033[1;36m⚠️  Findings\033[0m")
            for f in report.findings:
                sym = self.SEVERITY_SYM[f.severity]
                print(f"  {sym}  [{f.server_name}] {f.title}")
                if verbose:
                    print(f"               {f.description}")
                    print(f"               \033[36m💡 {f.recommendation}\033[0m")

        print()


# ═══════════════════════════════════════════════════════════════
# GUI APPLICATION
# ═══════════════════════════════════════════════════════════════

def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext

    class AgentScopeApp:
        BG = "#0D1117"; PNL = "#161B22"; CRD = "#1C2333"; INP = "#0D1117"
        FG = "#E6EDF3"; FG2 = "#8B949E"; DIM = "#484F58"
        ACC = "#00D4AA"; ACC2 = "#58A6FF"; PRP = "#BC8CFF"; BRD = "#30363D"

        def __init__(self, root):
            self.root = root
            self.engine = AgentScopeEngine()
            self.current_report = None
            self._setup_window()
            self._setup_styles()
            self._build_ui()

        def _setup_window(self):
            self.root.title("NEATLABS™ AGENT SCOPE — AI Agent Permission Auditor")
            self.root.geometry("1300x850")
            self.root.minsize(1000, 650)
            self.root.configure(bg=self.BG)
            try:
                self.root.tk_setPalette(background=self.BG, foreground=self.FG,
                    activeBackground=self.CRD, activeForeground=self.ACC)
            except Exception: pass
            try:
                import ctypes; self.root.update()
                hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int))
            except Exception: pass

        def _setup_styles(self):
            s = ttk.Style(); s.theme_use('clam')
            s.configure("Action.TButton", background=self.ACC, foreground=self.BG, font=("Consolas", 11, "bold"), padding=(20, 10))
            s.map("Action.TButton", background=[("active", self.ACC2)])
            s.configure("Sec.TButton", background=self.CRD, foreground=self.FG, font=("Consolas", 10), padding=(15, 8))
            s.map("Sec.TButton", background=[("active", self.BRD)])
            s.configure("Dark.TNotebook", background=self.BG, borderwidth=0)
            s.configure("Dark.TNotebook.Tab", background=self.PNL, foreground=self.FG2, font=("Consolas", 10, "bold"), padding=(20, 10))
            s.map("Dark.TNotebook.Tab", background=[("selected", self.CRD)], foreground=[("selected", self.ACC)])

        def _build_ui(self):
            # Top bar
            top = tk.Frame(self.root, bg=self.PNL, height=70); top.pack(fill="x"); top.pack_propagate(False)
            lf = tk.Frame(top, bg=self.PNL); lf.pack(side="left", padx=20, pady=10)
            tk.Label(lf, text="🔭", font=("Segoe UI Emoji", 24), bg=self.PNL).pack(side="left", padx=(0, 10))
            ts = tk.Frame(lf, bg=self.PNL); ts.pack(side="left")
            tk.Label(ts, text="NEATLABS™ AGENT SCOPE", font=("Consolas", 16, "bold"), fg=self.ACC, bg=self.PNL).pack(anchor="w")
            tk.Label(ts, text=f"AI Agent Permission & Access Auditor  •  v{__version__}", font=("Consolas", 9), fg=self.FG2, bg=self.PNL).pack(anchor="w")

            bf = tk.Frame(top, bg=self.PNL); bf.pack(side="right", padx=20)
            ttk.Button(bf, text="📁 Open Config", style="Action.TButton", command=self._open_file).pack(side="left", padx=4)
            ttk.Button(bf, text="🔍 Auto-Discover", style="Sec.TButton", command=self._auto_discover).pack(side="left", padx=4)
            ttk.Button(bf, text="📋 Paste JSON", style="Sec.TButton", command=self._paste_config).pack(side="left", padx=4)

            em = tk.Menubutton(bf, text="💾 Export ▾", font=("Consolas", 10), fg=self.FG, bg=self.CRD, relief="flat", padx=15, pady=8, cursor="hand2")
            emenu = tk.Menu(em, tearoff=0, bg=self.CRD, fg=self.FG, font=("Consolas", 10))
            emenu.add_command(label="📊  HTML Report", command=self._export_html)
            emenu.add_command(label="💾  JSON", command=self._export_json)
            em.configure(menu=emenu); em.pack(side="left", padx=4)

            tk.Frame(self.root, bg=self.ACC, height=2).pack(fill="x")

            # Notebook
            self.nb = ttk.Notebook(self.root, style="Dark.TNotebook")
            self.nb.pack(fill="both", expand=True)

            self.dash_tab = tk.Frame(self.nb, bg=self.BG); self.nb.add(self.dash_tab, text="  ⚡ DASHBOARD  ")
            self.servers_tab = tk.Frame(self.nb, bg=self.BG); self.nb.add(self.servers_tab, text="  🔭 SERVERS  ")
            self.findings_tab = tk.Frame(self.nb, bg=self.BG); self.nb.add(self.findings_tab, text="  ⚠️ FINDINGS  ")
            self.samples_tab = tk.Frame(self.nb, bg=self.BG); self.nb.add(self.samples_tab, text="  🧪 SAMPLES  ")
            self.help_tab = tk.Frame(self.nb, bg=self.BG); self.nb.add(self.help_tab, text="  📖 HELP  ")

            self._build_dashboard()
            self._build_samples()
            self._build_help()

            # Status
            sb = tk.Frame(self.root, bg=self.PNL, height=30); sb.pack(fill="x", side="bottom"); sb.pack_propagate(False)
            self.status = tk.Label(sb, text="  Ready — Open a config file, auto-discover, or try Samples", font=("Consolas", 9), fg=self.FG2, bg=self.PNL, anchor="w")
            self.status.pack(side="left", fill="x", expand=True)
            tk.Label(sb, text=f"v{__version__}  •  © NeatLabs™ SDVOSB  ", font=("Consolas", 9), fg=self.DIM, bg=self.PNL).pack(side="right")

        def _build_dashboard(self):
            c = tk.Frame(self.dash_tab, bg=self.BG); c.pack(fill="both", expand=True, padx=20, pady=20)
            self.dash_content = c
            self._show_welcome()

        def _show_welcome(self):
            for w in self.dash_content.winfo_children(): w.destroy()
            f = tk.Frame(self.dash_content, bg=self.PNL, padx=40, pady=40); f.pack(fill="x")
            tk.Label(f, text="Welcome to Agent Scope", font=("Consolas", 18, "bold"), fg=self.ACC, bg=self.PNL).pack()
            tk.Label(f, text="Audit what your AI agents can actually access.\n\n• Open a Claude Desktop / Cursor / MCP config file\n• Auto-discover configs on your system\n• Or try the Samples tab to see the auditor in action\n\nKeyboard: Ctrl+O (open) • Ctrl+D (discover)",
                font=("Consolas", 10), fg=self.FG2, bg=self.PNL, justify="center").pack(pady=(10, 0))

        def _build_samples(self):
            c = tk.Frame(self.samples_tab, bg=self.BG); c.pack(fill="both", expand=True, padx=20, pady=20)
            tk.Label(c, text="🧪 Sample Configurations", font=("Consolas", 14, "bold"), fg=self.ACC, bg=self.BG).pack(anchor="w")
            tk.Label(c, text="Load pre-built configs to see Agent Scope in action.\n", font=("Consolas", 10), fg=self.FG2, bg=self.BG).pack(anchor="w")

            samples = [
                ("✅  Minimal / Safe", "2 servers: memory + Brave search. Low-risk, no filesystem or code exec.", SAMPLE_SAFE, "#00E676"),
                ("💀  Overly Permissive", "7 servers: root filesystem, shell exec, prod database with plaintext creds,\nbrowser, AWS, unknown server, Slack. Maximum attack surface.", SAMPLE_RISKY, "#FF1744"),
                ("⚠️  Typical Developer Setup", "4 servers: scoped filesystem, GitHub, web fetch, SQLite.\nCommon config with a few things worth reviewing.", SAMPLE_TYPICAL, "#FFD600"),
            ]
            for title, desc, data, color in samples:
                card = tk.Frame(c, bg=self.CRD, padx=20, pady=15); card.pack(fill="x", pady=8)
                t = tk.Frame(card, bg=self.CRD); t.pack(fill="x")
                tk.Label(t, text=title, font=("Consolas", 12, "bold"), fg=color, bg=self.CRD).pack(side="left")
                tk.Button(t, text="⚡ AUDIT", font=("Consolas", 10, "bold"), fg=self.BG, bg=self.ACC, relief="flat", padx=15, pady=4, cursor="hand2",
                    command=lambda d=data, ti=title: self._scan_sample(d, ti)).pack(side="right")
                tk.Label(card, text=desc, font=("Consolas", 9), fg=self.FG2, bg=self.CRD, justify="left").pack(anchor="w", pady=(5, 0))

        def _build_help(self):
            f = tk.Frame(self.help_tab, bg=self.BG); f.pack(fill="both", expand=True)
            ht = scrolledtext.ScrolledText(f, wrap="word", bg=self.BG, fg=self.FG, font=("Consolas", 10), relief="flat", bd=0, padx=20, pady=20)
            ht.pack(fill="both", expand=True)
            ht.insert("1.0", HELP_TEXT)
            ht.config(state="disabled")

        # ── Actions ──

        def _open_file(self):
            fp = filedialog.askopenfilename(title="Open MCP Config", filetypes=[("JSON", "*.json"), ("All", "*.*")])
            if fp: self._run_audit_file(fp)

        def _auto_discover(self):
            configs = self.engine.discover_configs()
            if not configs:
                messagebox.showinfo("Not Found", "No MCP config files found automatically.\n\nTry opening a config file manually.")
                return
            if len(configs) == 1:
                self._run_audit_file(configs[0][0])
            else:
                win = tk.Toplevel(self.root); win.title("Select Config"); win.geometry("500x300"); win.configure(bg=self.BG)
                tk.Label(win, text=f"Found {len(configs)} configs:", font=("Consolas", 12, "bold"), fg=self.ACC, bg=self.BG).pack(padx=15, pady=10, anchor="w")
                for path, desc in configs:
                    tk.Button(win, text=f"{desc}\n{path}", font=("Consolas", 9), fg=self.FG, bg=self.CRD, relief="flat", padx=15, pady=8, cursor="hand2", justify="left",
                        command=lambda p=path, w=win: (w.destroy(), self._run_audit_file(p))).pack(fill="x", padx=15, pady=3)

        def _paste_config(self):
            win = tk.Toplevel(self.root); win.title("Paste MCP Config JSON"); win.geometry("600x400"); win.configure(bg=self.BG); win.transient(self.root)
            tk.Label(win, text="Paste your MCP config JSON:", font=("Consolas", 11, "bold"), fg=self.ACC, bg=self.BG).pack(padx=15, pady=(15, 5), anchor="w")
            ta = scrolledtext.ScrolledText(win, wrap="word", bg=self.INP, fg=self.FG, font=("Consolas", 10), insertbackground=self.ACC, relief="flat")
            ta.pack(fill="both", expand=True, padx=15, pady=5); ta.focus_set()
            def scan():
                try:
                    data = json.loads(ta.get("1.0", "end-1c"))
                    win.destroy()
                    self._run_audit_data(data, "<pasted config>")
                except json.JSONDecodeError as e:
                    messagebox.showerror("Invalid JSON", str(e))
            bf = tk.Frame(win, bg=self.BG); bf.pack(fill="x", padx=15, pady=15)
            tk.Button(bf, text="⚡ AUDIT", font=("Consolas", 11, "bold"), fg=self.BG, bg=self.ACC, relief="flat", padx=25, pady=8, command=scan, cursor="hand2").pack(side="right")

        def _scan_sample(self, data, title):
            self._run_audit_data(data, f"<sample: {title}>")

        def _run_audit_file(self, filepath):
            try:
                report = self.engine.audit(filepath)
                self.current_report = report
                self._display_report(report)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to audit:\n{e}")

        def _run_audit_data(self, data, label):
            # Write temp file and audit
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
                json.dump(data, tf)
                tf_path = tf.name
            try:
                report = self.engine.audit(tf_path)
                report.config_path = label
                self.current_report = report
                self._display_report(report)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to audit:\n{e}")
            finally:
                os.unlink(tf_path)

        def _display_report(self, report):
            self._populate_dashboard(report)
            self._populate_servers(report)
            self._populate_findings(report)
            self.nb.select(0)
            self.status.config(text=f"  {report.verdict} — {len(report.servers)} servers, {report.total_permissions} permissions, {len(report.findings)} findings | Score {report.risk_score:.0f}/100 | {report.scan_duration_ms:.1f}ms")

        def _populate_dashboard(self, r):
            for w in self.dash_content.winfo_children(): w.destroy()
            score = r.risk_score
            if score == 0: sc, sl = "#00E676", "CLEAN"
            elif score <= 20: sc, sl = "#00E5FF", "LOW RISK"
            elif score <= 50: sc, sl = "#FFD600", "MODERATE"
            elif score <= 80: sc, sl = "#FF6D00", "HIGH RISK"
            else: sc, sl = "#FF1744", "CRITICAL"

            # Score
            sf = tk.Frame(self.dash_content, bg=self.PNL); sf.pack(fill="x", pady=(0, 15))
            si = tk.Frame(sf, bg=self.PNL); si.pack(fill="x", padx=20, pady=15)
            tk.Label(si, text=f"{score:.0f}", font=("Consolas", 48, "bold"), fg=sc, bg=self.PNL).pack(side="left")
            tk.Label(si, text="/100", font=("Consolas", 18), fg=self.DIM, bg=self.PNL).pack(side="left", anchor="s", pady=(0, 12))
            di = tk.Frame(si, bg=self.PNL); di.pack(side="left", padx=(20, 0))
            tk.Label(di, text=sl, font=("Consolas", 14, "bold"), fg=sc, bg=self.PNL).pack(anchor="w")
            tk.Label(di, text=f"{len(r.servers)} servers • {r.total_permissions} permissions • {len(r.permission_categories)} categories",
                font=("Consolas", 10), fg=self.FG2, bg=self.PNL).pack(anchor="w")

            # Severity bar
            cb = tk.Frame(self.dash_content, bg=self.BG); cb.pack(fill="x", pady=(0, 15))
            for name, cnt, fg, bg in [("CRITICAL", r.critical_count, "#FF1744", SEVERITY_BG[Severity.CRITICAL]),
                                       ("HIGH", r.high_count, "#FF6D00", SEVERITY_BG[Severity.HIGH]),
                                       ("MEDIUM", r.medium_count, "#FFD600", SEVERITY_BG[Severity.MEDIUM]),
                                       ("LOW", r.low_count, "#00E5FF", SEVERITY_BG[Severity.LOW]),
                                       ("INFO", r.info_count, "#B0BEC5", SEVERITY_BG[Severity.INFO])]:
                c = tk.Frame(cb, bg=bg, padx=15, pady=10); c.pack(side="left", fill="x", expand=True, padx=3)
                tk.Label(c, text=str(cnt), font=("Consolas", 22, "bold"), fg=fg, bg=bg).pack()
                tk.Label(c, text=name, font=("Consolas", 8, "bold"), fg=fg, bg=bg).pack()

            # Permission matrix
            tk.Label(self.dash_content, text="🗺️  PERMISSION MATRIX", font=("Consolas", 11, "bold"), fg=self.ACC, bg=self.BG).pack(anchor="w", pady=(10, 5))
            for s in r.servers:
                cats = sorted(set(p.category for p in s.permissions), key=lambda c: c.value)
                rf = tk.Frame(self.dash_content, bg=self.CRD, padx=12, pady=8); rf.pack(fill="x", pady=2)
                risk_colors = {"CRITICAL": "#FF1744", "HIGH": "#FF6D00", "MEDIUM": "#FFD600", "LOW": "#00E5FF", "UNKNOWN": self.FG2}
                rc = risk_colors.get(s.risk_label, self.FG2)
                tk.Label(rf, text="●", font=("Consolas", 12), fg=rc, bg=self.CRD).pack(side="left")
                tk.Label(rf, text=f" {s.name}", font=("Consolas", 10, "bold"), fg=self.FG, bg=self.CRD).pack(side="left")
                for cat in cats:
                    tk.Label(rf, text=f" {PERM_ICONS.get(cat, '')} {cat.value}", font=("Consolas", 9), fg=self.FG2, bg=self.CRD).pack(side="left", padx=(8, 0))

        def _populate_servers(self, r):
            for w in self.servers_tab.winfo_children(): w.destroy()
            canvas = tk.Canvas(self.servers_tab, bg=self.BG, highlightthickness=0)
            scroll = ttk.Scrollbar(self.servers_tab, command=canvas.yview)
            inner = tk.Frame(canvas, bg=self.BG)
            inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.create_window((0, 0), window=inner, anchor="nw")
            canvas.configure(yscrollcommand=scroll.set)
            canvas.pack(side="left", fill="both", expand=True); scroll.pack(side="right", fill="y")
            canvas.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

            for s in r.servers:
                risk_colors = {"CRITICAL": "#FF1744", "HIGH": "#FF6D00", "MEDIUM": "#FFD600", "LOW": "#00E5FF", "UNKNOWN": self.FG2}
                rc = risk_colors.get(s.risk_label, self.FG2)
                card = tk.Frame(inner, bg=self.PNL, padx=15, pady=12); card.pack(fill="x", padx=10, pady=5)
                hdr = tk.Frame(card, bg=self.PNL); hdr.pack(fill="x")
                tk.Label(hdr, text="●", font=("Consolas", 14), fg=rc, bg=self.PNL).pack(side="left")
                tk.Label(hdr, text=f" {s.name}", font=("Consolas", 12, "bold"), fg=self.FG, bg=self.PNL).pack(side="left")
                tk.Label(hdr, text=f"  [{s.risk_label}]", font=("Consolas", 10, "bold"), fg=rc, bg=self.PNL).pack(side="left")
                if s.known:
                    tk.Label(hdr, text="  ✓ Known", font=("Consolas", 9), fg="#00E676", bg=self.PNL).pack(side="left")

                tk.Label(card, text=f"Package: {s.package}  •  {s.description}", font=("Consolas", 9), fg=self.FG2, bg=self.PNL).pack(anchor="w", pady=(4, 0))

                if s.permissions:
                    pf = tk.Frame(card, bg=self.PNL); pf.pack(fill="x", pady=(8, 0))
                    for p in s.permissions:
                        tk.Label(pf, text=f"  {PERM_ICONS.get(p.category, '')} {p.category.value}: {p.action} → {p.scope}",
                            font=("Consolas", 9), fg=self.ACC, bg=self.PNL, anchor="w").pack(anchor="w")

                for f in s.findings:
                    ff = tk.Frame(card, bg=SEVERITY_BG[f.severity], padx=10, pady=6); ff.pack(fill="x", pady=(6, 0))
                    tk.Label(ff, text=f" {f.severity.value} ", font=("Consolas", 8, "bold"), fg="#FFF", bg=SEVERITY_COLORS[f.severity], padx=4).pack(side="left")
                    tk.Label(ff, text=f"  {f.title}", font=("Consolas", 9, "bold"), fg=SEVERITY_COLORS[f.severity], bg=SEVERITY_BG[f.severity]).pack(side="left")

        def _populate_findings(self, r):
            for w in self.findings_tab.winfo_children(): w.destroy()
            canvas = tk.Canvas(self.findings_tab, bg=self.BG, highlightthickness=0)
            scroll = ttk.Scrollbar(self.findings_tab, command=canvas.yview)
            inner = tk.Frame(canvas, bg=self.BG)
            inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.create_window((0, 0), window=inner, anchor="nw")
            canvas.configure(yscrollcommand=scroll.set)
            canvas.pack(side="left", fill="both", expand=True); scroll.pack(side="right", fill="y")
            canvas.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

            if not r.findings:
                tk.Label(inner, text="\n\n  ✅  No findings — Configuration looks good!\n", font=("Consolas", 14, "bold"), fg="#00E676", bg=self.BG).pack(pady=30)
                return

            for f in r.findings:
                card = tk.Frame(inner, bg=SEVERITY_BG[f.severity], padx=15, pady=12); card.pack(fill="x", padx=10, pady=4)
                hdr = tk.Frame(card, bg=SEVERITY_BG[f.severity]); hdr.pack(fill="x")
                tk.Label(hdr, text=f" {f.severity.value} ", font=("Consolas", 8, "bold"), fg="#FFF", bg=SEVERITY_COLORS[f.severity], padx=6).pack(side="left")
                tk.Label(hdr, text=f"  {f.title}", font=("Consolas", 11, "bold"), fg=SEVERITY_COLORS[f.severity], bg=SEVERITY_BG[f.severity]).pack(side="left")
                tk.Label(hdr, text=f"[{f.server_name}]  ", font=("Consolas", 9), fg=self.FG2, bg=SEVERITY_BG[f.severity]).pack(side="right")
                tk.Label(card, text=f.description, font=("Consolas", 9), fg=self.FG, bg=SEVERITY_BG[f.severity], wraplength=700, justify="left").pack(fill="x", pady=(8, 0), anchor="w")
                tk.Label(card, text=f"💡 {f.recommendation}", font=("Consolas", 9), fg=self.ACC, bg=SEVERITY_BG[f.severity], wraplength=700, justify="left").pack(fill="x", pady=(6, 0), anchor="w")

        def _export_html(self):
            if not self.current_report: messagebox.showinfo("No Report", "Run an audit first."); return
            fp = filedialog.asksaveasfilename(title="Export HTML", defaultextension=".html", filetypes=[("HTML", "*.html")],
                initialfile=f"agent-scope-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html")
            if fp:
                try:
                    Path(fp).write_text(generate_html_report(self.current_report))
                    self.status.config(text=f"  ✅ HTML exported: {fp}")
                    import webbrowser
                    if messagebox.askyesno("Exported", f"Saved to {fp}\n\nOpen in browser?"): webbrowser.open(f"file://{os.path.abspath(fp)}")
                except Exception as e: messagebox.showerror("Error", str(e))

        def _export_json(self):
            if not self.current_report: messagebox.showinfo("No Report", "Run an audit first."); return
            fp = filedialog.asksaveasfilename(title="Export JSON", defaultextension=".json", filetypes=[("JSON", "*.json")],
                initialfile=f"agent-scope-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json")
            if fp:
                try:
                    Path(fp).write_text(json.dumps(self.current_report.to_dict(), indent=2))
                    self.status.config(text=f"  ✅ JSON exported: {fp}")
                except Exception as e: messagebox.showerror("Error", str(e))

    root = tk.Tk()
    app = AgentScopeApp(root)
    root.mainloop()


# ═══════════════════════════════════════════════════════════════
# HELP TEXT
# ═══════════════════════════════════════════════════════════════

HELP_TEXT = f"""
╔══════════════════════════════════════════════════════════════╗
║             NEATLABS™ AGENT SCOPE v{__version__} — HELP                 ║
╚══════════════════════════════════════════════════════════════╝

━━━ WHAT IS AGENT SCOPE? ━━━

Agent Scope audits what AI agents can actually do on your
system by analyzing MCP (Model Context Protocol) server
configurations, tool definitions, and agent manifests.

Think of it as "ls -la" for your AI agent's permissions.

When you connect MCP servers to Claude Desktop, Cursor, or
any MCP-compatible client, you're granting the AI agent
real capabilities: filesystem access, shell execution,
database queries, API calls, cloud management, and more.

Agent Scope maps all of this out and flags anything
overly permissive or dangerous.


━━━ WHAT CONFIGS DOES IT SCAN? ━━━

• Claude Desktop: claude_desktop_config.json
• Cursor: .cursor/mcp.json
• Project-level: .mcp.json, mcp.json, mcp_config.json
• Windsurf / Codeium configs
• Any JSON file with mcpServers definitions

Auto-Discover will check standard locations for your OS.


━━━ PERMISSION CATEGORIES ━━━

📁 Filesystem — Read, write, delete, traverse files
💻 Code Execution — Shell commands, script execution
🌐 Network — HTTP requests, API calls
🗄️ Database — SQL queries, document stores
🔑 Credentials — Keys, tokens, passwords
📧 Communication — Email, Slack, Discord
☁️ Cloud — AWS, GCP, Azure resource management
🔧 System — Process management, OS commands
🔍 Browser — Web browsing, page interaction
👤 Identity — Auth, user data access
💰 Financial — Payment, billing systems
💾 Data — Memory, knowledge stores


━━━ KNOWLEDGE BASE ━━━

Agent Scope recognizes 30+ popular MCP server packages and
knows their exact permission profiles. Unknown servers are
flagged and analyzed heuristically by name and arguments.


━━━ CLI USAGE ━━━

  python agent_scope.py --cli config.json
  python agent_scope.py --cli --auto-discover
  python agent_scope.py --cli config.json --html -o report.html
  python agent_scope.py --cli config.json --json -o report.json
  python agent_scope.py --cli config.json --verbose

Exit codes: 0 = clean/low | 1 = high | 2 = critical


━━━ ABOUT ━━━

NeatLabs™ is a Service-Disabled Veteran-Owned Small Business
specializing in cybersecurity, AI platform development, and
federal compliance consulting.

Website: neatlabs.ai
Contact: info@neatlabs.ai

Open source under the MIT License.
github.com/neatlabs/agent-scope

© {datetime.now().year} NeatLabs™ — All Rights Reserved
"""


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--cli':
        parser = argparse.ArgumentParser(prog="agent-scope",
            description="NeatLabs™ Agent Scope — AI Agent Permission Auditor")
        parser.add_argument('--cli', action='store_true')
        parser.add_argument('target', nargs='?', help='Config file path')
        parser.add_argument('--auto-discover', '-a', action='store_true', help='Auto-discover MCP configs')
        parser.add_argument('--json', '-j', action='store_true', help='JSON output')
        parser.add_argument('--html', action='store_true', help='HTML report')
        parser.add_argument('--output', '-o', help='Output file path')
        parser.add_argument('--verbose', '-v', action='store_true', help='Detailed output')
        parser.add_argument('--version', action='version', version=f'Agent Scope v{__version__}')
        args = parser.parse_args()
        if not args.target and not args.auto_discover:
            parser.error("Provide a config file path or use --auto-discover")
        cli = CLIRunner()
        sys.exit(cli.run(args))
    else:
        launch_gui()


if __name__ == "__main__":
    main()
