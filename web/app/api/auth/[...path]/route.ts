// Same-origin proxy to neon Auth. the SDK's handler sets the session cookie
// on this app's domain.
import { auth } from "../../../../lib/auth/server.ts";

export const { GET, POST, PUT, DELETE, PATCH } = auth.handler();
