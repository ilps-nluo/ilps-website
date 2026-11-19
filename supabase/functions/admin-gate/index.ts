// supabase/functions/admin-gate/index.ts
// Central gate for the ILPS admin panel.
// Actions (all POST, all re-check the central credentials):
//   verify : { action, centralEmail, centralPassword }
//   login  : { ..., email, password }               -> returns { session }
//   signup : { ..., displayName, email, password }  -> creates auth user + profile
import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const CENTRAL_EMAIL = (Deno.env.get("CENTRAL_EMAIL") ?? "").trim().toLowerCase();
const CENTRAL_PASSWORD = Deno.env.get("CENTRAL_PASSWORD") ?? "";

const MAX_FAILS = 10;
const WINDOW_MINUTES = 15;

const cors = {
  "Access-Control-Allow-Origin": "*", // tighten to the live site origin at deploy
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });

const admin = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false },
});

const str = (v: unknown) => (typeof v === "string" ? v : "");

async function sha256(value: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(value);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function safeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.min(a.length, b.length); i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function centralOk(email: string, password: string): Promise<boolean> {
  const emailMatch = safeEqual(
    await sha256(email.trim().toLowerCase()),
    await sha256(CENTRAL_EMAIL),
  );
  const passwordMatch = safeEqual(await sha256(password), await sha256(CENTRAL_PASSWORD));
  return emailMatch && passwordMatch;
}

async function recordFailure(ip: string) {
  await admin.from("gate_attempts").insert({ ip });
  const dayAgo = new Date(Date.now() - 24 * 60 * 60_000).toISOString();
  await admin.from("gate_attempts").delete().lt("created_at", dayAgo);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  if (!CENTRAL_EMAIL || !CENTRAL_PASSWORD) {
    return json({ error: "Server not configured" }, 500);
  }

  // Rate limit by IP
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
  const since = new Date(Date.now() - WINDOW_MINUTES * 60_000).toISOString();
  const { count } = await admin
    .from("gate_attempts")
    .select("id", { count: "exact", head: true })
    .eq("ip", ip)
    .gte("created_at", since);
  if ((count ?? 0) >= MAX_FAILS) {
    return json({ error: "Too many attempts. Try again later." }, 429);
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid request" }, 400);
  }

  // 1. Central gate
  if (!(await centralOk(str(body.centralEmail), str(body.centralPassword)))) {
    await recordFailure(ip);
    return json({ error: "Invalid credentials" }, 401);
  }

  const action = str(body.action);

  if (action === "verify") return json({ ok: true });

  // 2. Personal sign-in
  if (action === "login") {
    const anon = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
    const { data, error } = await anon.auth.signInWithPassword({
      email: str(body.email).trim(),
      password: str(body.password),
    });
    if (error || !data.session) {
      await recordFailure(ip);
      return json({ error: "Invalid credentials" }, 401);
    }

    const { data: profile } = await admin
      .from("profiles")
      .select("active")
      .eq("id", data.user.id)
      .maybeSingle();
    if (!profile) {
      await recordFailure(ip);
      return json({ error: "Invalid credentials" }, 401);
    }
    if (!profile.active) {
      return json({ error: "This profile is deactivated" }, 403);
    }

    return json({
      session: {
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
      },
    });
  }

  // 3. Profile creation
  if (action === "signup") {
    const displayName = str(body.displayName).trim();
    const email = str(body.email).trim().toLowerCase();
    const password = str(body.password);

    if (displayName.length < 1 || displayName.length > 80) {
      return json({ error: "Enter a display name (1 to 80 characters)" }, 400);
    }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return json({ error: "Enter a valid email" }, 400);
    }
    if (password.length < 10) {
      return json({ error: "Password must be at least 10 characters" }, 400);
    }

    const { data, error } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });
    if (error || !data.user) {
      return json({ error: error?.message ?? "Could not create profile" }, 400);
    }

    const { error: profileError } = await admin
      .from("profiles")
      .insert({ id: data.user.id, display_name: displayName });
    if (profileError) {
      await admin.auth.admin.deleteUser(data.user.id); // roll back the orphan user
      return json({ error: "Could not create profile" }, 500);
    }

    return json({ ok: true });
  }

  return json({ error: "Unknown action" }, 400);
});