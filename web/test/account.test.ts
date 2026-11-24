import { test } from "node:test";
import assert from "node:assert/strict";

import { accountMessage, checkPasswordChange, cleanName } from "../lib/account.ts";

test("password changes are checked before they reach the auth service", () => {
  assert.equal(checkPasswordChange("old-password", "short", "short"), "password-short");
  assert.equal(checkPasswordChange("old-password", "x".repeat(129), "x".repeat(129)), "password-short");
  assert.equal(checkPasswordChange("old-password", "new-password", "other-password"), "password-mismatch");
  assert.equal(checkPasswordChange("same-password", "same-password", "same-password"), "password-same");
  assert.equal(checkPasswordChange("old-password", "new-password", "new-password"), null);
});

test("names are trimmed and bounded", () => {
  assert.equal(cleanName("  Ada   Lovelace "), "Ada Lovelace");
  assert.equal(cleanName("   "), null);
  assert.equal(cleanName("a".repeat(101)), null);
});

test("only known status codes produce a message; free text is never echoed", () => {
  assert.equal(accountMessage("password-changed")?.tone, "success");
  assert.equal(accountMessage("password-wrong")?.tone, "error");
  assert.equal(accountMessage("<script>alert(1)</script>"), null);
  assert.equal(accountMessage("toString"), null, "prototype keys are not messages");
  assert.equal(accountMessage(undefined), null);
});

test("sign-in method statuses have fixed messages", async () => {
  const { accountMessage } = await import("../lib/account.ts");
  assert.equal(accountMessage("github-linked")?.tone, "success");
  assert.equal(accountMessage("github-link-failed")?.tone, "error");
  assert.equal(accountMessage("github-unlinked")?.tone, "success");
});

test("a GitHub link is judged by who started it and who came back", async () => {
  const { githubLinkOutcome, oauthErrorCode, accountMessage } = await import("../lib/account.ts");
  assert.equal(githubLinkOutcome(undefined, "u1", true), null, "no record: nothing is claimed");
  assert.equal(githubLinkOutcome("u1", "u1", true), "github-linked");
  assert.equal(githubLinkOutcome("u1", "u1", false), "github-not-linked");
  assert.equal(githubLinkOutcome("u1", "u2", true), "github-other-account");
  for (const s of ["github-not-linked", "github-other-account"]) assert.equal(accountMessage(s)?.tone, "error");
  assert.equal(oauthErrorCode("state_mismatch"), "state_mismatch");
  assert.equal(oauthErrorCode("<script>"), null);
});
