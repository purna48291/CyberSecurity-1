export function parseAuthEvent(row) {
  const required = ["timestamp", "username", "source_ip", "event"];
  const missing = required.filter((field) => !(field in row));

  if (missing.length > 0) {
    throw new Error(`Missing required fields: ${missing.join(", ")}`);
  }

  if (!["login_failed", "login_success"].includes(row.event)) {
    throw new Error(`Unsupported event type: ${row.event}`);
  }

  const timestamp = new Date(row.timestamp);
  if (Number.isNaN(timestamp.getTime())) {
    throw new Error(`Invalid timestamp: ${row.timestamp}`);
  }

  return {
    timestamp,
    username: String(row.username),
    sourceIp: String(row.source_ip),
    event: String(row.event),
    role: String(row.role ?? "user")
  };
}

export function createFinding({ ruleId, severity, title, description, evidence }) {
  return {
    ruleId,
    severity,
    title,
    description,
    evidence
  };
}
