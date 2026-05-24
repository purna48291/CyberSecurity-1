import { createFinding } from "./models.js";

const MINUTE = 60 * 1000;

export function detectBruteForce(events, { threshold = 5, windowMinutes = 10 } = {}) {
  const findings = [];
  const failuresByIp = new Map();

  for (const event of events) {
    if (event.event !== "login_failed") continue;
    const bucket = failuresByIp.get(event.sourceIp) ?? [];
    bucket.push(event);
    failuresByIp.set(event.sourceIp, bucket);
  }

  const windowMs = windowMinutes * MINUTE;
  for (const [sourceIp, failures] of failuresByIp.entries()) {
    const ordered = [...failures].sort((a, b) => a.timestamp - b.timestamp);

    for (let index = 0; index < ordered.length; index += 1) {
      const start = ordered[index];
      const windowEvents = ordered.slice(index).filter((event) => event.timestamp - start.timestamp <= windowMs);

      if (windowEvents.length >= threshold) {
        const users = [...new Set(windowEvents.map((event) => event.username))].sort();
        findings.push(createFinding({
          ruleId: "BRUTE_FORCE",
          severity: "high",
          title: "Likely brute-force attempt",
          description: `${sourceIp} produced ${windowEvents.length} failed logins within ${windowMinutes} minutes.`,
          evidence: [
            `first_seen=${windowEvents[0].timestamp.toISOString()}`,
            `last_seen=${windowEvents.at(-1).timestamp.toISOString()}`,
            `target_users=${users.join(", ")}`
          ]
        }));
        break;
      }
    }
  }

  return findings;
}

export function detectSuccessAfterFailures(events, { threshold = 3, windowMinutes = 15 } = {}) {
  const findings = [];
  const ordered = [...events].sort((a, b) => a.timestamp - b.timestamp);
  const windowMs = windowMinutes * MINUTE;

  for (const success of ordered) {
    if (success.event !== "login_success") continue;

    const recentFailures = ordered.filter((event) => (
      event.event === "login_failed"
      && event.username === success.username
      && event.sourceIp === success.sourceIp
      && success.timestamp - event.timestamp >= 0
      && success.timestamp - event.timestamp <= windowMs
    ));

    if (recentFailures.length >= threshold) {
      findings.push(createFinding({
        ruleId: "SUCCESS_AFTER_FAILURES",
        severity: "medium",
        title: "Successful login after repeated failures",
        description: `${success.username} logged in successfully from ${success.sourceIp} after ${recentFailures.length} failed attempts.`,
        evidence: [
          `success_time=${success.timestamp.toISOString()}`,
          `failed_attempts=${recentFailures.length}`
        ]
      }));
    }
  }

  return findings;
}

export function detectAdminAfterHours(events, { startHour = 8, endHour = 18 } = {}) {
  const findings = [];
  const adminRoles = new Set(["admin", "administrator"]);

  for (const event of events) {
    if (event.event !== "login_success") continue;
    if (!adminRoles.has(event.role.toLowerCase())) continue;

    const hour = event.timestamp.getUTCHours();
    if (hour >= startHour && hour < endHour) continue;

    findings.push(createFinding({
      ruleId: "ADMIN_AFTER_HOURS",
      severity: "medium",
      title: "Administrator login outside business hours",
      description: `${event.username} logged in from ${event.sourceIp} at ${event.timestamp.toISOString()}.`,
      evidence: [`role=${event.role}`, `utc_hour=${hour}`]
    }));
  }

  return findings;
}

export function runAllRules(events) {
  const severityOrder = new Map([
    ["critical", 0],
    ["high", 1],
    ["medium", 2],
    ["low", 3]
  ]);

  return [
    ...detectBruteForce(events),
    ...detectSuccessAfterFailures(events),
    ...detectAdminAfterHours(events)
  ].sort((a, b) => (severityOrder.get(a.severity) ?? 99) - (severityOrder.get(b.severity) ?? 99));
}
