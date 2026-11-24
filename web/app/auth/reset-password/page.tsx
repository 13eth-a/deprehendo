import { ResetPasswordForm } from "../../../components/AuthForms.tsx";
import { PublicHeader } from "../../../components/PublicHeader.tsx";

export const dynamic = "force-dynamic";

// Neon Auth's emailed link lands here as ?token=..., or ?error=INVALID_TOKEN
// when the link is stale. The token is passed to the form only if it looks
// like one; the auth service decides whether it is valid. Signed-in users
// may use this page too: it is how a GitHub-only account adds a password.
const TOKEN = /^[A-Za-z0-9_-]{8,256}$/;

export default async function ResetPassword({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const query = await searchParams;
  const raw = Array.isArray(query.token) ? query.token[0] : query.token;
  const token = raw && TOKEN.test(raw) ? raw : undefined;
  return (
    <>
      <PublicHeader current="auth" />
      <ResetPasswordForm token={token} linkError={Boolean(query.error) || (raw !== undefined && !token)} />
    </>
  );
}
