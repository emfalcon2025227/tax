#!/usr/bin/env node
import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";

const files = ["index.html", "admin.html", "login.html"];
let failed = false;

for (const file of files) {
  const source = fs.readFileSync(file, "utf8");
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let match;
  let index = 0;

  while ((match = scriptRe.exec(source)) !== null) {
    const attrs = match[1] || "";
    const body = match[2] || "";
    if (/\bsrc\s*=/.test(attrs) || !body.trim()) continue;

    index += 1;
    const tmp = path.join(".tmp", `validate-${path.basename(file)}-${index}.mjs`);
    fs.mkdirSync(".tmp", { recursive: true });
    fs.writeFileSync(tmp, body, "utf8");

    const result = spawnSync(process.execPath, ["--check", tmp], { encoding: "utf8" });
    if (result.status !== 0) {
      failed = true;
      console.error(`[HTML-JS] FAIL ${file} <script #${index}>\n${result.stderr || result.stdout}`);
    }
  }
}

try {
  fs.rmSync(".tmp", { recursive: true, force: true });
} catch {}

if (failed) {
  process.exit(1);
}

console.log("[HTML-JS] All inline scripts passed Node syntax validation.");
