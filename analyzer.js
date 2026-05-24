import { readFile } from "node:fs/promises";
import { parseAuthEvent } from "./models.js";
import { runAllRules } from "./rules.js";

export async function loadEvents(path) {
  const content = await readFile(path, "utf8");
  const events = [];

  content.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      events.push(parseAuthEvent(JSON.parse(trimmed)));
    } catch (error) {
      throw new Error(`${path}:${index + 1}: ${error.message}`);
    }
  });

  return events.sort((a, b) => a.timestamp - b.timestamp);
}

export async function analyze(path) {
  return runAllRules(await loadEvents(path));
}

export function renderReport(findings) {
  if (findings.length === 0) {
    return "# CyberWatch Lite Report\n\nNo findings detected.\n";
  }

  const lines = ["# CyberWatch Lite Report", "", `Findings detected: ${findings.length}`, ""];

  findings.forEach((finding, index) => {
    lines.push(`## ${index + 1}. ${finding.title}`);
    lines.push("");
    lines.push(`- Rule: \`${finding.ruleId}\``);
    lines.push(`- Severity: \`${finding.severity}\``);
    lines.push(`- Description: ${finding.description}`);
    lines.push("- Evidence:");
    finding.evidence.forEach((item) => lines.push(`  - \`${item}\``));
    lines.push("");
  });

  return lines.join("\n");
}
