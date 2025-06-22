// netlify/functions/validateForm.js

const blocked           = require("./blocked-domains");
const disposableDomains = require("disposable-email-domains");
const { parse }         = require("tldts");
const { resolveMx }     = require("dns").promises;

const FORM_ID = process.env.WEBFLOW_FORM_ID;
if (!FORM_ID) {
  throw new Error("Missing WEBFLOW_FORM_ID");
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

  // 2) Parse body (JSON or URL-encoded)
  const ct   = (event.headers["content-type"] || "").toLowerCase();
  const data = ct.includes("application/json")
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
    console.warn(`Blocked domain: ${email} → ${rootDomain}`);
    return cors(400, "Please use your company email.");
  }

  // 6) MX record check
  try {
    await resolveMx(domain);
  } catch {
    return cors(400, "Invalid email domain.");
  }

  // 7) Forward to your site’s form endpoint
  try {
    const siteRes = await fetch(
      `https://brylliantsolutions.com/form/${FORM_ID}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams(data).toString(),
      }
    );
    if (!siteRes.ok) {
      const text = await siteRes.text();
      console.error("Site form error:", siteRes.status, text);
      return cors(siteRes.status, `Submission error: ${text}`);
    }
  } catch (err) {
    console.error("Error forwarding to site form:", err);
    return cors(500, "Server error. Please try again.");
  }

  // 8) Success
  return cors(200, "OK");
};

// Helper to return a plain-text CORS response
function cors(statusCode, message) {
  return {
    statusCode,
    headers: {
      "Access-Control-Allow-Origin":  "*",
      "Access-Control-Allow-Methods": "POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type":                 "text/plain",
    },
    body: message,
  };
}
