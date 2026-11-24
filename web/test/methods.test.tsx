import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";

import { ResetPasswordForm, SignInForm, SignInMethodControls, SignUpForm, VerifyEmailStep } from "../components/AuthForms.tsx";
import { withRouter } from "./router.tsx";

const noop = async () => {};

test("a GitHub-only account is offered a password and cannot remove its last method", () => {
  const html = renderToStaticMarkup(withRouter(<SignInMethodControls email="a@b.dev" hasPassword={false} hasGitHub startGitHubLink={noop} />));
  assert.ok(html.includes("Email me a link to add one"));
  assert.ok(html.includes("Add a password before disconnecting"));
  assert.ok(!html.includes(">Disconnect<"));
});

test("an account with both methods can disconnect GitHub", () => {
  const html = renderToStaticMarkup(withRouter(<SignInMethodControls email="a@b.dev" hasPassword hasGitHub startGitHubLink={noop} />));
  assert.ok(html.includes("Disconnect"));
  assert.ok(!html.includes("Email me a link"));
});

test("a password-only account sees GitHub's state (the button needs NEXT_PUBLIC_AUTH_GITHUB=1 at build)", () => {
  const html = renderToStaticMarkup(withRouter(<SignInMethodControls email="a@b.dev" hasPassword hasGitHub={false} startGitHubLink={noop} />));
  const enabled = process.env.NEXT_PUBLIC_AUTH_GITHUB === "1";
  assert.equal(html.includes("Connect GitHub"), enabled);
  if (!enabled) assert.ok(html.includes("Not available on this deployment"));
});

test("password reset asks for an email without a token and for the new password with one", () => {
  const ask = renderToStaticMarkup(withRouter(<ResetPasswordForm />));
  assert.ok(ask.includes('name="email"') && !ask.includes('name="confirm"'));
  const set = renderToStaticMarkup(withRouter(<ResetPasswordForm token="abcdefgh12345678" />));
  assert.ok(set.includes('name="password"') && set.includes('name="confirm"'));
  const stale = renderToStaticMarkup(withRouter(<ResetPasswordForm linkError />));
  assert.ok(stale.includes("invalid or has expired"));
});

test("password fields can be shown and hidden, and stay password fields for managers", async () => {
  const { PasswordField } = await import("../components/PasswordField.tsx");
  const html = renderToStaticMarkup(<PasswordField name="password" label="Password" autoComplete="current-password" />);
  assert.ok(html.includes('type="password"') && html.includes('name="password"') && html.includes('autoComplete="current-password"'));
  assert.ok(html.includes('type="button"'), "the toggle never submits the form");
  assert.ok(html.includes('aria-pressed="false"') && html.includes(">Show<") && html.includes('aria-label="Show password"'));
  const signIn = renderToStaticMarkup(withRouter(<SignInForm />));
  const signUp = renderToStaticMarkup(withRouter(<SignUpForm />));
  for (const page of [signIn, signUp]) assert.ok(page.includes("uv-field__toggle"));
});

test("sign-up asks for a code only when Neon withheld the session", async () => {
  const { needsVerification, isUnverified } = await import("../components/AuthForms.tsx");
  assert.equal(needsVerification({ token: null, user: { emailVerified: false } }), true);
  assert.equal(needsVerification({ token: "t", user: { emailVerified: false } }), false, "verification optional: signed in");
  assert.equal(needsVerification({ token: null, user: { emailVerified: true } }), false);
  assert.equal(isUnverified({ status: 403, code: "EMAIL_NOT_VERIFIED" }), true);
  assert.equal(isUnverified({ status: 401 }), false);
  const step = renderToStaticMarkup(withRouter(<VerifyEmailStep email="a@b.dev" />));
  assert.ok(step.includes('autoComplete="one-time-code"') && step.includes('inputMode="numeric"'));
  assert.ok(step.includes("a@b.dev"));
});
