/**
 * Account settings: form checks and the fixed messages the account page shows
 * after an action. Actions redirect back with a short code (`?status=...`),
 * never with free text, so nothing a visitor types is echoed into the page.
 */

export const PASSWORD_MIN = 8;
export const PASSWORD_MAX = 128;
export const NAME_MAX = 100;
/** who started a GitHub link (app/account/actions.ts startGitHubLink) */
export const LINK_COOKIE = "deprehendo_link_from";

export type AccountStatus =
  | "name-saved"
  | "name-invalid"
  | "password-changed"
  | "password-mismatch"
  | "password-short"
  | "password-same"
  | "password-wrong"
  | "password-none"
  | "sessions-revoked"
  | "display-saved"
  | "github-linked"
  | "github-not-linked"
  | "github-other-account"
  | "github-link-failed"
  | "github-unlinked"
  | "failed";

const MESSAGES: Record<AccountStatus, { tone: "success" | "error"; text: string }> = {
  "name-saved": { tone: "success", text: "Your name was saved." },
  "name-invalid": { tone: "error", text: `Enter a name between 1 and ${NAME_MAX} characters.` },
  "password-changed": {
    tone: "success",
    text: "Your password was changed. Other devices were signed out; this one stays signed in.",
  },
  "password-mismatch": { tone: "error", text: "The new password and its confirmation do not match." },
  "password-short": {
    tone: "error",
    text: `Use a new password of ${PASSWORD_MIN} to ${PASSWORD_MAX} characters.`,
  },
  "password-same": { tone: "error", text: "The new password must be different from the current one." },
  "password-wrong": { tone: "error", text: "The current password is not correct." },
  "password-none": {
    tone: "error",
    text: "This account signs in with GitHub and has no deprehendo password to change.",
  },
  "sessions-revoked": { tone: "success", text: "All other devices were signed out." },
  "display-saved": { tone: "success", text: "Display settings saved for this browser." },
  "github-linked": { tone: "success", text: "GitHub is connected. You can sign in with it." },
  "github-not-linked": {
    tone: "error",
    text:
      "GitHub was not connected. Neon Auth links GitHub only when the GitHub account's verified primary email is this account's email, and this account's email is verified too. Use that GitHub account, or change its primary email, and try again.",
  },
  "github-other-account": {
    tone: "error",
    text:
      "That GitHub account belongs to a different deprehendo account, so you are now signed in to that one. Sign out, sign back in with your email and password, and connect a GitHub account whose verified email matches.",
  },
  "github-link-failed": { tone: "error", text: "GitHub sign-in did not finish, so nothing changed. Try again." },
  "github-unlinked": { tone: "success", text: "GitHub is disconnected. Sign in with your email and password." },
  failed: { tone: "error", text: "That did not work. Try again in a moment." },
};

/** The message for a status code from the URL, or null for anything unknown. */
export function accountMessage(code: string | undefined): { tone: "success" | "error"; text: string } | null {
  if (!code || !Object.hasOwn(MESSAGES, code)) return null;
  return MESSAGES[code as AccountStatus];
}

/** Checks a password change before it reaches the auth service. */
export function checkPasswordChange(current: string, next: string, confirm: string): AccountStatus | null {
  if (next.length < PASSWORD_MIN || next.length > PASSWORD_MAX) return "password-short";
  if (next !== confirm) return "password-mismatch";
  if (next === current) return "password-same";
  return null;
}

/** A trimmed display name, or null when it is empty or too long. */
export function cleanName(raw: string): string | null {
  const name = raw.trim().replace(/\s+/g, " ");
  return name.length >= 1 && name.length <= NAME_MAX ? name : null;
}

/**
 * The outcome of a GitHub link, from what is true after the round trip:
 * who started it, who is signed in now, and whether that account has GitHub.
 */
export function githubLinkOutcome(
  startedBy: string | undefined,
  nowUser: string,
  hasGitHub: boolean,
): "github-linked" | "github-not-linked" | "github-other-account" | null {
  if (!startedBy) return null;
  if (startedBy !== nowUser) return "github-other-account";
  return hasGitHub ? "github-linked" : "github-not-linked";
}

/** Better Auth's error code from an OAuth callback, shown only when it is a plain code. */
export function oauthErrorCode(raw: string | undefined): string | null {
  return raw && /^[a-z_]{1,48}$/.test(raw) ? raw : null;
}
