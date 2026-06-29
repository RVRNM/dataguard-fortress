#!/usr/bin/env node
/**
 * dataguard-fortress skill installer
 * Detects your AI agent and installs the skill to the right location.
 *
 * Usage:
 *   npx dataguard-fortress-skill
 *   npx dataguard-fortress-skill --agent claude
 *   npx dataguard-fortress-skill --agent all
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SKILL_SRC = path.join(__dirname, "SKILL.md");

const AGENTS = {
  claude: {
    name: "Claude Code",
    dirs: [".claude/skills"],
    files: { "dataguard-fortress.md": SKILL_SRC },
  },
  codex: {
    name: "OpenAI Codex CLI",
    dirs: [".codex/skills"],
    files: { "SKILL.md": SKILL_SRC },
  },
  cursor: {
    name: "Cursor",
    dirs: [".cursor/rules"],
    files: { "dataguard-fortress.mdc": SKILL_SRC },
  },
  aider: {
    name: "Aider",
    dirs: [".aider/skills"],
    files: { "dataguard-fortress.md": SKILL_SRC },
  },
  cline: {
    name: "Cline / Claude Dev",
    dirs: [".cline/skills"],
    files: { "dataguard-fortress.md": SKILL_SRC },
  },
  continue: {
    name: "Continue.dev",
    dirs: [".continue/skills"],
    files: { "dataguard-fortress.md": SKILL_SRC },
  },
  opencode: {
    name: "OpenCode",
    dirs: [".opencode/skills"],
    files: { "dataguard-fortress.md": SKILL_SRC },
  },
  hermes: {
    name: "Hermes Agent",
    dirs: [".hermes/skills"],
    files: { "dataguard-fortress.md": SKILL_SRC },
  },
};

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

function installToAgent(agent, targetDir) {
  const config = AGENTS[agent];
  if (!config) return false;
  for (const dir of config.dirs) {
    const fullDir = path.resolve(targetDir, dir);
    fs.mkdirSync(fullDir, { recursive: true });
    for (const [destName, srcPath] of Object.entries(config.files)) {
      const dest = path.join(fullDir, destName);
      fs.copyFileSync(srcPath, dest);
    }
  }
  return true;
}

function main() {
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

  const targetDir = process.cwd();
  let installed = 0;

  for (const agent of agents) {
    const config = AGENTS[agent];
    if (!config) {
      console.log(`  ❌ Unknown agent: ${agent}`);
      continue;
    }
    const ok = installToAgent(agent, targetDir);
    if (ok) {
      console.log(`  ✅ Installed for ${config.name}`);
      installed++;
    }
  }

  console.log(`\n${installed} skill(s) installed to ${targetDir}`);
  console.log("\nRestart your AI agent to load the skill.\n");
}

main();
