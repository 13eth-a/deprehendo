"use client";
// Email-and-password sign-in, sign-up and sign-out (contract §8.2). The SDK
// reports some failures by throwing an AuthApiError and others in the
// { data, error } result, so both are handled (seen in web/scripts/auth-smoke.ts).
// The forms say method="post": if the page's JavaScript has not loaded, a
// native submit must never put the email and password in the URL.
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useRouter } from "next/navigation";

import { authClient } from "../lib/auth/client.ts";
import { Spinner } from "./uiverse/Loaders.tsx";
import { PasswordField } from "./PasswordField.tsx";

type AuthError = { message?: string; status?: number; code?: string } | null | undefined;

function messageFor(error: AuthError, fallback: string): string {
  if (!error) return fallback;
  if (error.status === 401) return "That email and password do not match an account.";
  if (error.status === 422 || error.code === "USER_ALREADY_EXISTS") return "An account with that email already exists. Sign in instead.";
  return error.message || fallback;
}

async function attempt(fn: () => Promise<{ error?: AuthError }>): Promise<AuthError> {
  try {
    const result = await fn();
    return result?.error ?? null;
  } catch (err) {
    return (err as AuthError) ?? { message: "Request failed" };
  }
}

export const GITHUB_ENABLED = process.env.NEXT_PUBLIC_AUTH_GITHUB === "1";

// Better Auth account endpoints the Neon SDK proxies (link-social,
// unlink-account, request-password-reset, reset-password). Typed here by
// hand, as Better Auth documents them, so a loose SDK type does not leak.
type Result = Promise<{ data?: unknown; error?: AuthError }>;
const accounts = authClient as unknown as {
  unlinkAccount(body: { providerId: string }): Result;
  requestPasswordReset(body: { email: string; redirectTo: string }): Result;
  emailOtp: {
    sendVerificationOtp(body: { email: string; type: "email-verification" }): Result;
    verifyEmail(body: { email: string; otp: string }): Result;
  };
  getSession(): Promise<{ data?: { session?: unknown } | null; error?: AuthError }>;
  resetPassword(body: { newPassword: string; token: string }): Result;
};

function GitHubButton() {
  if (!GITHUB_ENABLED) return null;
  return (
    <p className="auth__alt">
      <button
        type="button"
        className="uv-button auth__wide"
        onClick={() => {
          // Absolute URLs, as Neon's guide uses: the redirect back comes from
          // Neon's callback route, so it must name this app's origin, which
          // must be a trusted domain in Neon Auth.
          const origin = window.location.origin;
          void attempt(() =>
            authClient.signIn.social({
              provider: "github",
              callbackURL: `${origin}/incidents`,
              errorCallbackURL: `${origin}/auth/sign-in`,
            }),
          );
        }}
      >
        Continue with GitHub
      </button>
    </p>
  );
}

export function SignInForm({
  passwordReset = false,
  verified = false,
}: { passwordReset?: boolean; verified?: boolean } = {}) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unverified, setUnverified] = useState<{ email: string; password: string } | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "");
    const password = String(form.get("password") ?? "");
    setPending(true);
    setError(null);
    const failure = await attempt(() => authClient.signIn.email({ email, password }));
    setPending(false);
    if (failure && isUnverified(failure)) {
      // The password was right; the email still needs its code.
      setUnverified({ email, password });
      return;
    }
    if (failure) {
      setError(messageFor(failure, "Sign-in failed. Try again."));
      return;
    }
    router.replace("/incidents");
    router.refresh();
  }

  if (unverified) {
    return <VerifyEmailStep email={unverified.email} password={unverified.password} sendOnOpen />;
  }

  return (
    <AuthFrame titleId="sign-in-title" title="Sign in to deprehendo" lede="Open your organization's incidents.">
      {passwordReset && (
        <p role="status" className="notice notice--success">Your password is set. Sign in with it now.</p>
      )}
      {verified && (
        <p role="status" className="notice notice--success">Your email is verified. Sign in to continue.</p>
      )}
      <form method="post" onSubmit={onSubmit} aria-describedby={error ? "auth-error" : undefined}>
        <label className="uv-field">
          <input className="uv-input" name="email" type="email" autoComplete="email" required />
          <span>Email</span>
        </label>
        <PasswordField name="password" label="Password" autoComplete="current-password" />
        <button className="uv-button uv-button--primary auth__wide" type="submit" disabled={pending}>
          {pending && <Spinner />}
          {pending ? "Signing in…" : "Sign in"}
        </button>
      </form>
      {error && <p id="auth-error" role="alert" className="auth__error">{error}</p>}
      <p className="auth__forgot"><a href="/auth/reset-password">Forgot your password?</a></p>
      <GitHubButton />
      <p className="auth__switch">No account? <a href="/auth/sign-up">Create one</a></p>
    </AuthFrame>
  );
}

export function SignUpForm() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [verify, setVerify] = useState<{ email: string; password: string } | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "");
    const password = String(form.get("password") ?? "");
    if (password.length < 8 || password.length > 128) {
      setError("Use a password of 8 to 128 characters.");
      return;
    }
    setPending(true);
    setError(null);
    let result: { data?: unknown; error?: AuthError };
    try {
      result = (await authClient.signUp.email({
        name: String(form.get("name") ?? ""),
        email,
        password,
        // used only if Neon is set to verify by link rather than by code
        callbackURL: `${window.location.origin}/incidents`,
      } as Parameters<typeof authClient.signUp.email>[0])) as { data?: unknown; error?: AuthError };
    } catch (err) {
      result = { error: (err as AuthError) ?? { message: "Request failed" } };
    }
    setPending(false);
    if (result.error) {
      setError(messageFor(result.error, "Sign-up failed. Try again."));
      return;
    }
    if (needsVerification(result.data)) {
      setVerify({ email, password });
      return;
    }
    router.replace("/incidents");
    router.refresh();
  }

  if (verify) {
    // Neon Auth already sent the code with the sign-up.
    return <VerifyEmailStep email={verify.email} password={verify.password} />;
  }

  return (
    <AuthFrame titleId="sign-up-title" title="Create your deprehendo account" lede="An organization owner adds you to their incidents after sign-up.">
      <form method="post" onSubmit={onSubmit} aria-describedby={error ? "auth-error" : undefined}>
        <label className="uv-field">
          <input className="uv-input" name="name" type="text" autoComplete="name" required />
          <span>Name</span>
        </label>
        <label className="uv-field">
          <input className="uv-input" name="email" type="email" autoComplete="email" required />
          <span>Email</span>
        </label>
        <PasswordField name="password" label="Password (8 characters or more)" autoComplete="new-password" minLength={8} maxLength={128} />
        <button className="uv-button uv-button--primary auth__wide" type="submit" disabled={pending}>
          {pending && <Spinner />}
          {pending ? "Creating account…" : "Create account"}
        </button>
      </form>
      {error && <p id="auth-error" role="alert" className="auth__error">{error}</p>}
      <GitHubButton />
      <p className="auth__switch">Already have an account? <a href="/auth/sign-in">Sign in</a></p>
    </AuthFrame>
  );
}

export function SignOutButton() {
  const router = useRouter();
  return (
    <button
      type="button"
      className="uv-button uv-button--ghost uv-button--sm sign-out"
      onClick={async () => {
        await attempt(() => authClient.signOut());
        router.replace("/");
        router.refresh();
      }}
    >
      Sign out
    </button>
  );
}

/** The auth forms sit on a plain sheet: one column, left-aligned, no ornament. */
/**
 * Password reset, both halves. Without a token: ask for the email and have
 * Neon Auth send a link. With the token from that link: set the new password.
 * The same flow gives an account that signs in only with GitHub its first
 * password. The request answers the same whether or not the email has an
 * account, so the page does not reveal who is registered.
 */
export function ResetPasswordForm({ token, linkError }: { token?: string; linkError?: boolean }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(linkError ? "That link is invalid or has expired. Ask for a new one." : null);
  const [sent, setSent] = useState(false);

  async function request(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const email = String(new FormData(event.currentTarget).get("email") ?? "");
    setPending(true);
    setError(null);
    const failure = await attempt(() =>
      accounts.requestPasswordReset({ email, redirectTo: `${window.location.origin}/auth/reset-password` }),
    );
    setPending(false);
    if (failure && failure.status !== 404) {
      setError(messageFor(failure, "The link could not be sent. Try again in a moment."));
      return;
    }
    setSent(true);
  }

  async function reset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") ?? "");
    if (password.length < 8 || password.length > 128) {
      setError("Use a password of 8 to 128 characters.");
      return;
    }
    if (password !== String(form.get("confirm") ?? "")) {
      setError("The two passwords do not match.");
      return;
    }
    setPending(true);
    setError(null);
    const failure = await attempt(() => accounts.resetPassword({ newPassword: password, token: token! }));
    setPending(false);
    if (failure) {
      setError(
        failure.status === 400 || failure.code === "INVALID_TOKEN"
          ? "That link is invalid or has expired. Ask for a new one."
          : messageFor(failure, "The password could not be set. Try again."),
      );
      return;
    }
    router.replace("/auth/sign-in?reset=1");
  }

  if (token) {
    return (
      <AuthFrame titleId="reset-title" title="Set a new password" lede="It replaces any password this account had, and signs out other devices.">
        <form method="post" onSubmit={reset} aria-describedby={error ? "auth-error" : undefined}>
          <PasswordField name="password" label="New password (8+ characters)" autoComplete="new-password" minLength={8} maxLength={128} />
          <PasswordField name="confirm" label="Confirm new password" autoComplete="new-password" minLength={8} maxLength={128} />
          <button className="uv-button uv-button--primary auth__wide" type="submit" disabled={pending}>
            {pending && <Spinner />}
            {pending ? "Saving…" : "Set password"}
          </button>
        </form>
        {error && <p id="auth-error" role="alert" className="auth__error">{error}</p>}
      </AuthFrame>
    );
  }
  return (
    <AuthFrame titleId="reset-title" title="Reset your password" lede="We will email you a link to set a new password. It also works for an account that so far signs in only with GitHub.">
      {sent ? (
        <p role="status" className="notice notice--success">
          If that email has a deprehendo account, a link is on its way. It expires in an hour.
        </p>
      ) : (
        <form method="post" onSubmit={request} aria-describedby={error ? "auth-error" : undefined}>
          <label className="uv-field">
            <input className="uv-input" name="email" type="email" autoComplete="email" required />
            <span>Email</span>
          </label>
          <button className="uv-button uv-button--primary auth__wide" type="submit" disabled={pending}>
            {pending && <Spinner />}
            {pending ? "Sending…" : "Email me a link"}
          </button>
        </form>
      )}
      {error && <p id="auth-error" role="alert" className="auth__error">{error}</p>}
      <p className="auth__switch"><a href="/auth/sign-in">Back to sign in</a></p>
    </AuthFrame>
  );
}

/**
 * Account → Sign-in methods: connect or disconnect GitHub, and add a password
 * to a GitHub-only account (through the emailed link, since setting a
 * password needs proof of the email). Disconnecting is offered only when
 * another method remains, so nobody locks themselves out.
 */
export function SignInMethodControls({
  email,
  hasPassword,
  hasGitHub,
  startGitHubLink,
}: {
  email: string;
  hasPassword: boolean;
  hasGitHub: boolean;
  /** server action (app/account/actions.ts), passed in so this client file imports no server code */
  startGitHubLink: () => Promise<void>;
}) {
  const router = useRouter();
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  const back = (status: string) => {
    router.replace(`/account?status=${status}`);
    router.refresh();
  };

  async function connect() {
    setPending("github");
    setError(null);
    const origin = window.location.origin;
    try {
      await startGitHubLink();
    } catch {
      setPending(null);
      setError("GitHub could not be connected. Reload the page and try again.");
      return;
    }
    // The working GitHub sign-in flow; Neon Auth links it to this account
    // when the verified emails match. On success the browser leaves for
    // GitHub, and the account page checks the result on return.
    const failure = await attempt(() =>
      authClient.signIn.social({
        provider: "github",
        callbackURL: `${origin}/account?status=github-check`,
        errorCallbackURL: `${origin}/account?status=github-link-failed`,
      }),
    );
    if (failure) {
      setPending(null);
      setError(messageFor(failure, "GitHub could not be connected. Try again."));
    }
  }

  async function disconnect() {
    setPending("unlink");
    setError(null);
    const failure = await attempt(() => accounts.unlinkAccount({ providerId: "github" }));
    setPending(null);
    if (failure) {
      setError(messageFor(failure, "GitHub could not be disconnected. Try again."));
      return;
    }
    back("github-unlinked");
  }

  async function addPassword() {
    setPending("password");
    setError(null);
    const failure = await attempt(() =>
      accounts.requestPasswordReset({ email, redirectTo: `${window.location.origin}/auth/reset-password` }),
    );
    setPending(null);
    if (failure) {
      setError(messageFor(failure, "The link could not be sent. Try again in a moment."));
      return;
    }
    setSent(true);
  }

  return (
    <div className="methods">
      <ul className="methods__list">
        <li>
          <div>
            <p className="strong">Email and password</p>
            <p className="muted small">{hasPassword ? `Signs in as ${email}.` : "Not set up."}</p>
          </div>
          {!hasPassword &&
            (sent ? (
              <p role="status" className="small">Link sent to {email}.</p>
            ) : (
              <button type="button" className="uv-button uv-button--sm" onClick={addPassword} disabled={pending !== null}>
                {pending === "password" && <Spinner />}
                Email me a link to add one
              </button>
            ))}
        </li>
        <li>
          <div>
            <p className="strong">GitHub</p>
            <p className="muted small">
              {hasGitHub
                ? "Connected."
                : GITHUB_ENABLED
                  ? `Not connected. Use a GitHub account whose verified email is ${email}.`
                  : "Not available on this deployment."}
            </p>
          </div>
          {hasGitHub ? (
            hasPassword ? (
              <button type="button" className="uv-button uv-button--sm" onClick={disconnect} disabled={pending !== null}>
                {pending === "unlink" && <Spinner />}
                Disconnect
              </button>
            ) : (
              <span className="muted small">Add a password before disconnecting.</span>
            )
          ) : (
            GITHUB_ENABLED && (
              <button type="button" className="uv-button uv-button--sm" onClick={connect} disabled={pending !== null}>
                {pending === "github" && <Spinner />}
                Connect GitHub
              </button>
            )
          )}
        </li>
      </ul>
      {error && <p role="alert" className="auth__error">{error}</p>}
    </div>
  );
}

/** Better Auth refuses sign-in for an unverified email with 403 EMAIL_NOT_VERIFIED. */
export function isUnverified(error: AuthError): boolean {
  return Boolean(error && (error.code === "EMAIL_NOT_VERIFIED" || error.status === 403));
}

/**
 * Sign-up returns no session token while the email still has to be verified
 * (Neon: Settings → Auth → Verify at Sign-up). Without that setting it signs
 * the user straight in, and this is false.
 */
export function needsVerification(data: unknown): boolean {
  const d = data as { token?: string | null; user?: { emailVerified?: boolean } } | null | undefined;
  if (!d) return false;
  return !d.token && d.user?.emailVerified !== true;
}

const RESEND_SECONDS = 30;

/**
 * "Check your email": the 6-digit code Neon Auth sends when verification is
 * on (method: verification code). On success the user is signed in: by Neon
 * when auto sign-in after verification is on, otherwise with the password
 * they just typed, which stays in memory only for this step.
 */
export function VerifyEmailStep({
  email,
  password,
  sendOnOpen = false,
}: {
  email: string;
  password?: string;
  sendOnOpen?: boolean;
}) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [wait, setWait] = useState(sendOnOpen ? 0 : RESEND_SECONDS);
  const sentOnce = useRef(false);

  useEffect(() => {
    if (wait <= 0) return;
    const t = setTimeout(() => setWait((w) => w - 1), 1000);
    return () => clearTimeout(t);
  }, [wait]);

  async function send() {
    setError(null);
    const failure = await attempt(() => accounts.emailOtp.sendVerificationOtp({ email, type: "email-verification" }));
    if (failure) {
      setError(messageFor(failure, "The code could not be sent. Try again in a moment."));
      return;
    }
    setNotice(`A new code is on its way to ${email}.`);
    setWait(RESEND_SECONDS);
  }

  useEffect(() => {
    if (sendOnOpen && !sentOnce.current) {
      sentOnce.current = true;
      void send();
    }
    // send is stable for this email; run once on open
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sendOnOpen]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const otp = String(new FormData(event.currentTarget).get("otp") ?? "").replace(/\s+/g, "");
    if (!/^\d{6}$/.test(otp)) {
      setError("Enter the 6-digit code from the email.");
      return;
    }
    setPending(true);
    setError(null);
    const failure = await attempt(() => accounts.emailOtp.verifyEmail({ email, otp }));
    if (failure) {
      setPending(false);
      const code = failure.code ?? "";
      setError(
        code === "OTP_EXPIRED"
          ? "That code has expired. Send a new one."
          : code === "TOO_MANY_ATTEMPTS"
            ? "Too many wrong codes. Send a new one."
            : "That code is not right. Check the latest email and try again.",
      );
      return;
    }
    // Signed in already (auto sign-in after verification)? Otherwise sign in now.
    let session: unknown = null;
    try {
      session = (await accounts.getSession())?.data?.session ?? null;
    } catch {
      session = null;
    }
    if (!session && password) {
      const signInFailure = await attempt(() => authClient.signIn.email({ email, password }));
      session = signInFailure ? null : true;
    }
    setPending(false);
    if (session) {
      router.replace("/incidents");
      router.refresh();
    } else {
      router.replace("/auth/sign-in?verified=1");
    }
  }

  return (
    <AuthFrame titleId="verify-title" title="Check your email" lede={`Enter the 6-digit code sent to ${email} to finish setting up your account.`}>
      {notice && <p role="status" className="notice notice--success">{notice}</p>}
      <form method="post" onSubmit={onSubmit} aria-describedby={error ? "auth-error" : undefined}>
        <label className="uv-field">
          <input
            className="uv-input uv-otp"
            name="otp"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9 ]{6,7}"
            maxLength={7}
            required
            autoFocus
          />
          <span>Verification code</span>
        </label>
        <button className="uv-button uv-button--primary auth__wide" type="submit" disabled={pending}>
          {pending && <Spinner />}
          {pending ? "Verifying…" : "Verify email"}
        </button>
      </form>
      {error && <p id="auth-error" role="alert" className="auth__error">{error}</p>}
      <p className="auth__forgot">
        <button type="button" className="uv-button uv-button--ghost uv-button--sm" onClick={send} disabled={wait > 0}>
          {wait > 0 ? `Send a new code (${wait}s)` : "Send a new code"}
        </button>
      </p>
      <p className="auth__switch muted small">
        Got a link instead of a code? Open it; it verifies the email the same way. Wrong address?{" "}
        <a href="/auth/sign-up">Start again</a>
      </p>
    </AuthFrame>
  );
}

function AuthFrame({ titleId, title, lede, children }: { titleId: string; title: string; lede: string; children: ReactNode }) {
  return (
    <main className="auth" aria-labelledby={titleId}>
      <div className="auth__sheet">
        <h1 id={titleId}>{title}</h1>
        <p className="auth__lede">{lede}</p>
        {children}
      </div>
    </main>
  );
}
