import { defineConfig } from "@neon/config/v1";

export default defineConfig({
  // declare your neon services here
  // managed better auth (contract §8.2): email/password now, GitHub next.
  auth: true,
  buckets: {
    // "private" is the default; use "public_read" for anonymous reads
    assets: { access: "private" },
  },
  // branch policy: per-branch tuning
  branch: (branch) => {
    if (branch.isDefault) {
      // default branch: no overrides, uses project defaults
      return {};
    }
    if (!branch.exists) {
      // new non-default branches: auto-expire
      // run `neon checkout <name>` to create a new branch with these settings
      return { ttl: "7d" };
    }
    // existing branch: no changes
    return {};
  },
});
