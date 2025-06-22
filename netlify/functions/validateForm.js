// netlify/functions/validateForm.js
const blocked           = require("./blocked-domains");
const disposableDomains = require("disposable-email-domains");
const { parse }         = require("tldts");
const { resolveMx }     = require("dns").promises;

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

  // 2) Parse form-encoded body
  const data = Object.fromEntries(new URLSearchParams(event.body));

  // 3) Honeypot
  if (data.hp_name) {
    return cors(400, "Bot detected.");
  }

  // 4) Blocklist & disposable check
  const email      = (data.Email || data.email || "").trim().toLowerCase();
  const domain     = email.split("@")[1] || "";
  const rootDomain = parse(domain).domain || "";
  if (!rootDomain || blocked.includes(rootDomain) || disposableDomains.includes(rootDomain)) {
    return cors(400, "Please use your company email.");
  }

  // 5) MX record check
  try {
    await resolveMx(domain);
  } catch {
    return cors(400, "Invalid email domain.");
  }

  // 6) All good
  return cors(200, "OK");
};

function cors(statusCode, msg) {
  return {
    statusCode,
    headers: {
      "Access-Control-Allow-Origin":  "*",
      "Access-Control-Allow-Methods": "POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type":                 "text/plain",
    },
    body: msg,
  };
}