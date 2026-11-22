"use client";
// browser auth client. it takes no arguments: it talks to this app's own
// /api/auth proxy, never to neon directly (neon's skill: do not pass options).
import { createAuthClient } from "@neon/auth/next";

export const authClient = createAuthClient();
