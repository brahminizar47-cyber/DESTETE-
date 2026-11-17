import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function getSecretKey(): string | null {
  const legacy = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (legacy) return legacy;
  try {
    const keys = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") || "{}");
    return keys.default || null;
  } catch {
    return null;
  }
}

function getPublishableKey(): string | null {
  const legacy = Deno.env.get("SUPABASE_ANON_KEY");
  if (legacy) return legacy;
  try {
    const keys = JSON.parse(Deno.env.get("SUPABASE_PUBLISHABLE_KEYS") || "{}");
    return keys.default || null;
  } catch {
    return null;
  }
}

function getAuthTime(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const claims = JSON.parse(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")));
    return typeof claims.auth_time === "number" ? claims.auth_time : null;
  } catch {
    return null;
  }
}

async function collectFiles(
  admin: ReturnType<typeof createClient>,
  bucket: string,
  prefix: string,
): Promise<string[]> {
  const paths: string[] = [];
  let offset = 0;
  while (true) {
    const { data, error } = await admin.storage.from(bucket).list(prefix, {
      limit: 100,
      offset,
      sortBy: { column: "name", order: "asc" },
    });
    if (error) throw new Error("Could not inspect account storage.");
    for (const item of data || []) {
      const path = prefix ? prefix + "/" + item.name : item.name;
      if (item.id === null) {
        paths.push(...await collectFiles(admin, bucket, path));
      } else {
        paths.push(path);
      }
    }
    if (!data || data.length < 100) break;
    offset += 100;
  }
  return paths;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const authHeader = req.headers.get("Authorization") || "";
    const accessToken = authHeader.replace(/^Bearer\s+/i, "");
    if (!accessToken) return json({ error: "Authentication required" }, 401);

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const publishableKey = getPublishableKey();
    const secretKey = getSecretKey();
    if (!supabaseUrl || !publishableKey || !secretKey) {
      return json({ error: "Server configuration is incomplete" }, 500);
    }

    const userClient = createClient(supabaseUrl, publishableKey, {
      global: { headers: { Authorization: "Bearer " + accessToken } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: userData, error: userError } = await userClient.auth.getUser(accessToken);
    if (userError || !userData.user) return json({ error: "Invalid session" }, 401);

    // getUser verifies the JWT signature; auth_time is read only after that verification.
    const authTime = getAuthTime(accessToken);
    const now = Math.floor(Date.now() / 1000);
    if (!authTime || authTime > now + 60 || now - authTime > 15 * 60) {
      return json({ error: "For security, sign out and sign in again before deleting your account." }, 403);
    }

    const body = await req.json().catch(() => ({}));
    if (body?.confirmation !== "DELETE") {
      return json({ error: "Explicit deletion confirmation is required." }, 400);
    }

    const admin = createClient(supabaseUrl, secretKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const userId = userData.user.id;

    // The database's user-owned foreign keys cascade on Auth user deletion.
    const { error: deleteError } = await admin.auth.admin.deleteUser(userId);
    if (deleteError) {
      console.error("Auth user deletion failed:", deleteError);
      return json({ error: "The account could not be deleted. Please contact platform administration." }, 500);
    }

    // Storage is separate from Postgres/Auth. Clean up both account folders after
    // Auth deletion; report cleanup separately if Storage is temporarily unavailable.
    let storageCleanupPending = false;
    for (const bucket of ["profile-photos", "property-images"]) {
      try {
        const files = await collectFiles(admin, bucket, userId);
        for (let i = 0; i < files.length; i += 100) {
          const { error } = await admin.storage.from(bucket).remove(files.slice(i, i + 100));
          if (error) throw error;
        }
      } catch (storageError) {
        storageCleanupPending = true;
        console.error("Account storage cleanup pending:", bucket, storageError);
      }
    }

    return json({ success: true, storageCleanupPending });
  } catch (error) {
    console.error("Account deletion error:", error);
    return json({
      error: error instanceof Error ? error.message : "Unexpected account deletion error.",
    }, 500);
  }
});
