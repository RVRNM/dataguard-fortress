#!/usr/bin/env node
/**
 * dataguard-fortress skill installer
 * Detects your AI agent and installs the skill to the right location.
 *
 * Usage:
 *   npx dataguard-fortress-skill
 *   npx dataguard-fortress-skill --agent claude
 *   npx dataguard-fortress-skill --agent all
 *
 * Works without npm login — fetches SKILL.md from GitHub raw content.
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import https from "https";
import http from "http";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SKILL_MD_URL = "https://raw.githubusercontent.com/RVRNM/dataguard-fortress/main/skills/dataguard-fortress/SKILL.md";

const AGENTS = {
  claude: {
    name: "Claude Code",
    dirs: [".claude/skills"],
    files: { "dataguard-fortress.md": "SKILL.md" },
  },
  codex: {
    name: "OpenAI Codex CLI",
    dirs: [".codex/skills"],
    files: { "SKILL.md": "SKILL.md" },
  },
  cursor: {
    name: "Cursor",
    dirs: [".cursor/rules"],
    files: { "dataguard-fortress.mdc": "SKILL.md" },
  },
  aider: {
    name: "Aider",
    dirs: [".aider/skills"],
    files: { "dataguard-fortress.md": "SKILL.md" },
  },
  cline: {
    name: "Cline / Claude Dev",
    dirs: [".cline/skills"],
    files: { "dataguard-fortress.md": "SKILL.md" },
  },
  continue: {
    name: "Continue.dev",
    dirs: [".continue/skills"],
    files: { "dataguard-fortress.md": "SKILL.md" },
  },
  opencode: {
    name: "OpenCode",
    dirs: [".opencode/skills"],
    files: { "dataguard-fortress.md": "SKILL.md" },
  },
  hermes: {
    name: "Hermes Agent",
    dirs: [".hermes/skills"],
    files: { "dataguard-fortress.md": "SKILL.md" },
  },
};

function fetch(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith("https") ? https : http;
    mod.get(url, { headers: { "User-Agent": "dataguard-skill-installer" } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetch(res.headers.location).then(resolve).catch(reject);
      }
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve(data));
    }).on("error", reject);
  });
}

function detectAgents() {
  const cwd = process.cwd();
  const detected = [];
  if (fs.existsSync(path.join(cwd, ".claude"))) detected.push("claude");
  if (fs.existsSync(path.join(cwd, ".codex"))) detected.push("codex");
  if (fs.existsSync(path.join(cwd, ".cursor"))) detected.push("cursor");
  if (fs.existsSync(path.join(cwd, ".aider"))) detected.push("aider");
  if (fs.existsSync(path.join(cwd, ".cline"))) detected.push("cline");
  if (fs.existsSync(path.join(cwd, ".continue"))) detected.push("continue");
  if (fs.existsSync(path.join(cwd, ".opencode"))) detected.push("opencode");
  const home = process.env.HOME || process.env.USERPROFILE;
  if (home && fs.existsSync(path.join(home, ".hermes"))) detected.push("hermes");
  return [...new Set(detected)];
}

function installToAgent(agent, targetDir, skillContent) {
  const config = AGENTS[agent];
  if (!config) return false;
  for (const dir of config.dirs) {
    const fullDir = path.resolve(targetDir, dir);
    fs.mkdirSync(fullDir, { recursive: true });
    for (const destName of Object.keys(config.files)) {
      const dest = path.join(fullDir, destName);
      fs.writeFileSync(dest, skillContent, "utf-8");
    }
  }
  return true;
}

async function main() {
  const args = process.argv.slice(2);
  const agentArg = args.find((a) => !a.startsWith("--")) || args.find((a) => a.startsWith("--agent="))?.split("=")[1];

  console.log("\n🛡️  DataGuard Fortress Skill Installer\n");

  let agents = [];
  if (agentArg && agentArg !== "all") {
    agents = [agentArg];
  } else {
    agents = detectAgents();
    if (agents.length === 0) {
      console.log("No AI agent detected. Installing to ALL known locations...\n");
      agents = Object.keys(AGENTS);
    }
  }

  console.log("Fetching SKILL.md from GitHub...");
  let skillContent;
  try {
    skillContent = await fetch(SKILL_MD_URL);
    console.log(`  ✅ Downloaded (${skillContent.length} bytes)\n`);
  } catch (err) {
    console.log(`  ❌ Failed to fetch SKILL.md: ${err.message}`);
    console.log("  Make sure you have internet access.\n");
    process.exit(1);
  }

  const targetDir = process.cwd();
  let installed = 0;

  for (const agent of agents) {
    const config = AGENTS[agent];
    if (!config) {
      console.log(`  ❌ Unknown agent: ${agent}`);
      continue;
    }
    const ok = installToAgent(agent, targetDir, skillContent);
    if (ok) {
      console.log(`  ✅ Installed for ${config.name}`);
      installed++;
    }
  }

  console.log(`\n${installed} skill(s) installed to ${targetDir}`);
  console.log("\nRestart your AI agent to load the skill.\n");
}

main();
