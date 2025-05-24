// netlify/functions/validateForm.js
const blocked = require("./blocked-domains");
const dns     = require("dns").promises;

const FORM_ID   = process.env.WEBFLOW_FORM_ID;
const API_TOKEN = process.env.WEBFLOW_API_TOKEN;
const RC_SECRET = process.env.RECAPTCHA_SECRET_KEY;

exports.handler = async (event) => {
  // 1) Parse the body depending on content-type
  const contentType = event.headers["content-type"] || event.headers["Content-Type"] || "";
  let data;
  if (contentType.includes("application/json")) {
    data = JSON.parse(event.body || "{}");
  } else if (contentType.includes("application/x-www-form-urlencoded")) {
    data = Object.fromEntries(new URLSearchParams(event.body));
  } else {
    // fallback—try JSON
    try { data = JSON.parse(event.body || "{}"); }
    catch { data = {}; }
  }

  // 2) Extract the email from either form field name
  const rawEmail = (data.email ?? data.Email ?? "").trim();
  const email    = rawEmail.toLowerCase();
  const domain   = email.split("@")[1] || "";

  // 3) Honeypot
  if (data.hp_name) {
    return { statusCode: 400, body: "Bot detected." };
  }

  // 4) Blocklist
  if (!domain || blocked.includes(domain)) {
    return { statusCode: 400, body: "Please use your company email." };
  }

  // 5) MX lookup
  try {
    await dns.resolveMx(domain);
  } catch {
    return { statusCode: 400, body: "Invalid email domain." };
  }

  // 6) Verify reCAPTCHA v3
  const token = data["g-recaptcha-response"];
  const rcRes = await fetch(
    `https://www.google.com/recaptcha/api/siteverify?secret=${RC_SECRET}&response=${token}`,
    { method: "POST" }
  ).then(r => r.json());

  if (!rcRes.success || rcRes.score < 0.5) {
    return { statusCode: 400, body: "reCAPTCHA failed." };
  }

  // 7) Forward to Webflow
  await fetch(`https://api.webflow.com/form/${FORM_ID}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_TOKEN}`
    },
    body: JSON.stringify(data)
  });

  return { statusCode: 200, body: "OK" };
};
