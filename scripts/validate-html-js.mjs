import fs from "node:fs";

const files = ["index.html", "admin.html"];

for (const file of files) {
  const html = fs.readFileSync(file, "utf8");
  const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)].map(match => match[1]);

  if (scripts.length === 0) {
    throw new Error(file + ": no script blocks found.");
  }

  scripts.forEach((source, index) => {
    try {
      new Function(source);
    } catch (error) {
      throw new Error(file + ": script #" + index + " syntax error: " + error.message);
    }
  });

  console.log(file + ": " + scripts.length + " script block(s) passed syntax validation.");
}

console.log("Embedded HTML JavaScript validation passed.");
