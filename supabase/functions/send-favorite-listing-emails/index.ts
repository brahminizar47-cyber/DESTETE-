import { createClient } from "npm:@supabase/supabase-js@2.119.0";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char] ?? char);

Deno.serve(async (request: Request) => {
  if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const workerSecret = Deno.env.get("EMAIL_WORKER_SECRET");
  const suppliedSecret = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!workerSecret || !suppliedSecret || suppliedSecret !== workerSecret) {
    return json({ error: "Unauthorized" }, 401);
  }

  const resendKey = Deno.env.get("RESEND_API_KEY");
  const fromEmail = Deno.env.get("RESEND_FROM_EMAIL");
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  let serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!serviceKey) {
    try {
      const keys = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") ?? "{}");
      serviceKey = keys.default;
    } catch {
      serviceKey = undefined;
    }
  }

  if (!resendKey || !fromEmail || !supabaseUrl || !serviceKey) {
    return json({ error: "Email worker is not fully configured" }, 503);
  }

  const supabase = createClient(supabaseUrl, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { data: messages, error: claimError } = await supabase.rpc(
    "claim_favorite_listing_email_batch",
    { p_limit: 25 },
  );
  if (claimError) return json({ error: "Could not claim email queue", detail: claimError.message }, 500);

  let sent = 0;
  let failed = 0;
  for (const item of messages ?? []) {
    if (!item.recipient_email) {
      await supabase.rpc("fail_favorite_listing_email", {
        p_queue_id: item.queue_id,
        p_error: "Recipient account has no email address",
      });
      failed++;
      continue;
    }

    const subject = String(item.notification_title ?? "تحديث في عقار محفوظ");
    const propertyTitle = String(item.property_title ?? "عقار محفوظ");
    const bodyText = String(item.notification_body ?? "تم تحديث إعلان محفوظ في DESTATE.");
    const html = `
      <div dir="rtl" lang="ar" style="font-family:Arial,sans-serif;line-height:1.8;color:#202124;max-width:600px;margin:auto">
        <h2>${escapeHtml(subject)}</h2>
        <p>تم تحديث العقار الذي أضفته إلى المفضّلة على DESTATE.</p>
        <p><strong>${escapeHtml(propertyTitle)}</strong></p>
        <p>${escapeHtml(bodyText)}</p>
        <p><a href="https://destete.vercel.app/" style="display:inline-block;padding:10px 18px;background:#1f4b43;color:#fff;text-decoration:none;border-radius:8px">زيارة DESTATE</a></p>
        <p style="font-size:12px;color:#666">تصلك هذه الرسالة لأنك أضفت هذا العقار إلى المفضّلة.</p>
      </div>`;

    try {
      const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${resendKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: fromEmail,
          to: [item.recipient_email],
          subject,
          html,
        }),
      });
      const responseBody = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(`Resend ${response.status}: ${JSON.stringify(responseBody).slice(0, 700)}`);
      }
      const { error: completeError } = await supabase.rpc("complete_favorite_listing_email", {
        p_queue_id: item.queue_id,
      });
      if (completeError) throw new Error(`Email sent but queue acknowledgement failed: ${completeError.message}`);
      sent++;
    } catch (error) {
      await supabase.rpc("fail_favorite_listing_email", {
        p_queue_id: item.queue_id,
        p_error: error instanceof Error ? error.message : "Unknown email error",
      });
      failed++;
    }
  }

  return json({ claimed: messages?.length ?? 0, sent, failed });
});
