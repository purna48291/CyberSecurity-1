#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { analyze, renderReport } from "./analyzer.js";

function printUsage() {
  console.log("Usage: node src/cli.js <logfile> [--output <report.md>]");
}

function parseArgs(argv) {
  const args = [...argv];
  const logfile = args.shift();
  const outputIndex = args.indexOf("--output");
  const output = outputIndex >= 0 ? args[outputIndex + 1] : undefined;

  if (!logfile || args.includes("--help") || args.includes("-h")) {
    return { help: true };
  }

  if (outputIndex >= 0 && !output) {
    throw new Error("--output requires a file path");
  }

  return { logfile, output };
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) {
    printUsage();
    return 0;
  }

  const findings = await analyze(args.logfile);
  const report = renderReport(findings);

  if (args.output) {
    await writeFile(args.output, report, "utf8");
  } else {
    console.log(report);
  }

  return 0;
}

main().then((code) => {
  process.exitCode = code;
}).catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
});
