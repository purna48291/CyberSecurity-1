import assert from "node:assert/strict";
import test from "node:test";
import {
  detectAdminAfterHours,
  detectBruteForce,
  detectSuccessAfterFailures
} from "../src/rules.js";

function event(timestamp, username, sourceIp, eventType, role = "user") {
  return {
    timestamp: new Date(timestamp),
    username,
    sourceIp,
    event: eventType,
    role
  };
}

test("detects brute force from a single IP", () => {
  const events = Array.from({ length: 5 }, (_, minute) => (
    event(`2026-05-09T01:0${minute}:00Z`, "admin", "203.0.113.5", "login_failed")
  ));

  const findings = detectBruteForce(events);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "BRUTE_FORCE");
});

test("detects successful login after repeated failures", () => {
  const events = [
    event("2026-05-09T10:00:00Z", "alex", "192.0.2.2", "login_failed"),
    event("2026-05-09T10:01:00Z", "alex", "192.0.2.2", "login_failed"),
    event("2026-05-09T10:02:00Z", "alex", "192.0.2.2", "login_failed"),
    event("2026-05-09T10:03:00Z", "alex", "192.0.2.2", "login_success")
  ];

  const findings = detectSuccessAfterFailures(events);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "SUCCESS_AFTER_FAILURES");
});

test("detects administrator login after hours", () => {
  const events = [
    event("2026-05-09T02:30:00Z", "admin", "198.51.100.9", "login_success", "administrator")
  ];

  const findings = detectAdminAfterHours(events);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "ADMIN_AFTER_HOURS");
});
