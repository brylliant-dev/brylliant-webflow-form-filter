// netlify/functions/validateForm.js

const blocked           = require("./blocked-domains");
const disposableDomains = require("disposable-email-domains");
const { parse }         = require("tldts");
const { resolveMx }     = require("dns").promises;

const FORM_ID   = process.env.WEBFLOW_FORM_ID;
const API_TOKEN = process.env.WEBFLOW_API_TOKEN;
if (!FORM_ID || !API_TOKEN) {
  throw new Error("Missing WEBFLOW_FORM_ID or WEBFLOW_API_TOKEN");
}

exports.handler = async (event) => {
  // --- CORS preflight ---
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    };
  }

  // parse body (JSON or form-encoded)
  const ct = (event.headers["content-type"] || "").toLowerCase();
  const data = ct.includes("application/json")
    ? JSON.parse(event.body || "{}")
    : Object.fromEntries(new URLSearchParams(event.body));

  const rawEmail  = (data.email || data.Email || "").trim();
  const email     = rawEmail.toLowerCase();
  const domain    = email.split("@")[1] || "";
  const rootDomain = parse(domain).domain || "";

  // 1) honeypot
  if (data.hp_name) {
    return cors(400, "Bot detected.");
  }

  // 2) blocklist & disposable
  if (
    !rootDomain ||
    blocked.includes(rootDomain) ||
    disposableDomains.includes(rootDomain)
  ) {
    console.warn(`Blocked domain: ${email} → ${rootDomain}`);
    return cors(400, "Please use your company email.");
  }

  // 3) MX record check
  try {
    await resolveMx(domain);
  } catch {
    return cors(400, "Invalid email domain.");
  }

  // 4) forward to Webflow
  await fetch(`https://api.webflow.com/form/${FORM_ID}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_TOKEN}`,
    },
    body: JSON.stringify(data),
  });

  // 5) success
  return cors(200, "OK");
};

// helper to add CORS header
function cors(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Content-Type": "text/plain",
    },
    body,
  };
}