import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

const files = ["index.html", "admin.html", "login.html"];
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tax-html-js-"));

try {
  for (const file of files) {
    const source = fs.readFileSync(file, "utf8");
    const scripts = [...source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)];

    for (let i = 0; i < scripts.length; i++) {
      const code = scripts[i][1].trim();
      if (!code) continue;

      const tempFile = path.join(tempDir, `${file.replace(/\.html$/i, "")}-script-${i}.js`);
      fs.writeFileSync(tempFile, code, "utf8");

      try {
        execFileSync(process.execPath, ["--check", tempFile], { stdio: "pipe" });
      } catch (error) {
        const stderr = error?.stderr?.toString?.() || String(error);
        throw new Error(`${file} script #${i} failed syntax validation:\n${stderr}`);
      }
    }
  }
  console.log("HTML embedded JavaScript syntax validation passed.");
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true });
}
