// netlify/functions/validateForm.js

const blocked       = require("./blocked-domains");
const { resolveMx } = require("dns").promises;

const FORM_ID   = process.env.WEBFLOW_FORM_ID;
const API_TOKEN = process.env.WEBFLOW_API_TOKEN;

if (!FORM_ID || !API_TOKEN) {
  throw new Error("Missing WEBFLOW_FORM_ID or WEBFLOW_API_TOKEN");
}

exports.handler = async (event) => {
  // parse JSON or form-encodedn
  const ct = (event.headers["content-type"]||"").toLowerCase();
  const data = ct.includes("application/json")
    ? JSON.parse(event.body||"{}")
    : Object.fromEntries(new URLSearchParams(event.body));

  const { parse } = require("tldts");  
  // normalize email
  const rawEmail = (data.email ?? data.Email ?? "").trim();
  const email    = rawEmail.toLowerCase();

  const domain   = email.split("@")[1] || "";
  const rootDomain = parse(domain).domain || "";

  // 1) honeypot
  if (data.hp_name) return { statusCode:400, body:"Bot detected." };

  // 2) blocklist
  if (!rootDomain || blocked.includes(rootDomain)) {
    console.warn(`Blocked domain attempt: ${email} → ${rootDomain}`);
    return { statusCode: 400, body: "Please use your company email." };
  }

  // 3) MX check
  try { await resolveMx(domain) }
  catch { return { statusCode:400, body:"Invalid email domain." } }

  // 4) forward into Webflow
  await fetch(`https://api.webflow.com/form/${FORM_ID}`, {
    method: "POST",
    headers: {
      "Content-Type":"application/json",
      "Authorization":`Bearer ${API_TOKEN}`
    },
    body: JSON.stringify(data)
  });

  // 5) all good
  return { statusCode:200, body:"OK" };
};
