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
  // 1) CORS preflight
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

  // 2) Parse incoming data
  const contentType = (event.headers["content-type"] || "").toLowerCase();
  const data = contentType.includes("application/json")
    ? JSON.parse(event.body || "{}")
    : Object.fromEntries(new URLSearchParams(event.body));

  // 3) Honeypot
  if (data.hp_name) {
    return cors(400, "Bot detected.");
  }

  // 4) Email normalization + domain extraction
  const rawEmail   = (data.email || data.Email || "").trim();
  const email      = rawEmail.toLowerCase();
  const domain     = email.split("@")[1] || "";
  const rootDomain = parse(domain).domain || "";

  // 5) Blocklist & disposable check
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

  // 7) Forward to Webflow v1 submissions endpoint
  try {
    const wfRes = await fetch(`https://api.webflow.com/form/${FORM_ID}`, {
      method: "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${API_TOKEN}`,
        // this header is required even on the v1 endpoint
        "accept-version": "1.0.0",
      },
      body: JSON.stringify(data),
    });

    const text = await wfRes.text();
    console.log("Webflow API v1 response:", wfRes.status, text);

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
