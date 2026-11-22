"use client";
// Email-and-password sign-in, sign-up and sign-out (contract §8.2). the SDK
// reports some failures by throwing an AuthApiError and others in the
// { data, error } result, so both are handled (seen in web/scripts/auth-smoke.ts).
import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";

import { authClient } from "../lib/auth/client.ts";

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

const GITHUB_ENABLED = process.env.NEXT_PUBLIC_AUTH_GITHUB === "1";

function GitHubButton() {
  if (!GITHUB_ENABLED) return null;
  return (
    <p>
      <button
        type="button"
        className="button"
        onClick={() => {
          // absolute URLs, as neon's guide uses: the redirect back comes from
          // neon's callback route, so it must name this app's origin, which
          // must be a trusted domain in neon Auth.
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

export function SignInForm() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setPending(true);
    setError(null);
    const failure = await attempt(() =>
      authClient.signIn.email({ email: String(form.get("email") ?? ""), password: String(form.get("password") ?? "") }),
    );
    setPending(false);
    if (failure) {
      setError(messageFor(failure, "Sign-in failed. Try again."));
      return;
    }
    router.replace("/incidents");
    router.refresh();
  }

  return (
    <main className="auth" aria-labelledby="sign-in-title">
      <h1 id="sign-in-title">Sign in to deprehendo</h1>
      <form onSubmit={onSubmit} aria-describedby={error ? "auth-error" : undefined}>
        <label>
          Email
          <input name="email" type="email" autoComplete="email" required />
        </label>
        <label>
          Password
          <input name="password" type="password" autoComplete="current-password" required />
        </label>
        <button type="submit" disabled={pending}>{pending ? "Signing in…" : "Sign in"}</button>
      </form>
      {error && <p id="auth-error" role="alert">{error}</p>}
      <GitHubButton />
      <p>No account? <a href="/auth/sign-up">Create one</a></p>
    </main>
  );
}

export function SignUpForm() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") ?? "");
    if (password.length < 8) {
      setError("Use a password of at least 8 characters.");
      return;
    }
    setPending(true);
    setError(null);
    const failure = await attempt(() =>
      authClient.signUp.email({
        name: String(form.get("name") ?? ""),
        email: String(form.get("email") ?? ""),
        password,
      }),
    );
    setPending(false);
    if (failure) {
      setError(messageFor(failure, "Sign-up failed. Try again."));
      return;
    }
    router.replace("/incidents");
    router.refresh();
  }

  return (
    <main className="auth" aria-labelledby="sign-up-title">
      <h1 id="sign-up-title">Create your deprehendo account</h1>
      <form onSubmit={onSubmit} aria-describedby={error ? "auth-error" : undefined}>
        <label>
          Name
          <input name="name" type="text" autoComplete="name" required />
        </label>
        <label>
          Email
          <input name="email" type="email" autoComplete="email" required />
        </label>
        <label>
          Password
          <input name="password" type="password" autoComplete="new-password" minLength={8} required />
        </label>
        <button type="submit" disabled={pending}>{pending ? "Creating account…" : "Create account"}</button>
      </form>
      {error && <p id="auth-error" role="alert">{error}</p>}
      <GitHubButton />
      <p>Already have an account? <a href="/auth/sign-in">Sign in</a></p>
    </main>
  );
}

export function SignOutButton() {
  const router = useRouter();
  return (
    <button
      type="button"
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
