// netlify/functions/validateForm.js

const blocked           = require("./blocked-domains");
const disposableDomains = require("disposable-email-domains");
const { parse }         = require("tldts");
const { resolveMx }     = require("dns").promises;

const SITE_ID   = process.env.WEBFLOW_SITE_ID;
const FORM_ID   = process.env.WEBFLOW_FORM_ID;
const API_TOKEN = process.env.WEBFLOW_API_TOKEN;

if (!SITE_ID || !FORM_ID || !API_TOKEN) {
  throw new Error(
    "Missing one of: WEBFLOW_SITE_ID, WEBFLOW_FORM_ID or WEBFLOW_API_TOKEN"
  );
}

exports.handler = async (event) => {
  // 1) Handle CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
      body: "",
    };
  }

  // 2) Parse incoming body (form-urlencoded or JSON)
  const ct   = (event.headers["content-type"] || "").toLowerCase();
  const data = ct.includes("application/json")
    ? JSON.parse(event.body || "{}")
    : Object.fromEntries(new URLSearchParams(event.body));

  // 3) Honeypot
  if (data.hp_name) {
    return cors(400, "Bot detected.");
  }

  // 4) Normalize & extract email domain
  const rawEmail   = (data.email || data.Email || "").trim();
  const email      = rawEmail.toLowerCase();
  const domain     = email.split("@")[1] || "";
  const rootDomain = parse(domain).domain || "";

  // 5) Blocklist / disposable check
  if (
    !rootDomain ||
    blocked.includes(rootDomain) ||
    disposableDomains.includes(rootDomain)
  ) {
    console.warn(`Blocked domain attempt: ${email} → ${rootDomain}`);
    return cors(400, "Please use your company email.");
  }

  // 6) MX record check
  try {
    await resolveMx(domain);
  } catch {
    return cors(400, "Invalid email domain.");
  }

  // 7) Forward to Webflow v2 submissions endpoint
  try {
    const wfRes = await fetch(
      `https://api.webflow.com/sites/${SITE_ID}/forms/${FORM_ID}/submissions`,
      {
        method: "POST",
        headers: {
          "Content-Type":  "application/json",
          "Authorization": `Bearer ${API_TOKEN}`,
          "Accept-Version":"1.0.0",
        },
        body: JSON.stringify(data),
      }
    );

    const text = await wfRes.text();
    console.log("Webflow API v2 response:", wfRes.status, text);

    if (!wfRes.ok) {
      return cors(wfRes.status, `Webflow error: ${text}`);
    }
  } catch (err) {
    console.error("Error forwarding to Webflow API:", err);
    return cors(500, "Server error. Please try again.");
  }

  // 8) Success
  return cors(200, "OK");
};

// Helper to return a plain-text CORS response
function cors(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Access-Control-Allow-Origin":  "*",
      "Access-Control-Allow-Methods": "POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type":                 "text/plain",
    },
    body,
  };
}