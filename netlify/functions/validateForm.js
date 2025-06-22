// netlify/functions/validateForm.js

const blocked           = require("./blocked-domains");
const disposableDomains = require("disposable-email-domains");
const { parse }         = require("tldts");
const { resolveMx }     = require("dns").promises;

const ELEMENT_ID = process.env.WEBFLOW_ELEMENT_ID;
if (!ELEMENT_ID) {
  throw new Error("Missing WEBFLOW_ELEMENT_ID");
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

  // 2) Parse incoming data (JSON or URL-encoded)
  const ct   = (event.headers["content-type"] || "").toLowerCase();
  const data = ct.includes("application/json")
    ? JSON.parse(event.body || "{}")
    : Object.fromEntries(new URLSearchParams(event.body));

  // 3) Honeypot
  if (data.hp_name) {
    return cors(400, "Bot detected.");
  }

  // 4) Email/domain checks (blocklist + MX)
  const rawEmail   = (data.email || data.Email || "").trim();
  const email      = rawEmail.toLowerCase();
  const domain     = email.split("@")[1] || "";
  const rootDomain = parse(domain).domain || "";

  if (
    !rootDomain ||
    require("./blocked-domains").includes(rootDomain) ||
    require("disposable-email-domains").includes(rootDomain)
  ) {
    return cors(400, "Please use your company email.");
  }

  try {
    await resolveMx(domain);
  } catch {
    return cors(400, "Invalid email domain.");
  }

  // 5) Forward to the published-site form endpoint
  try {
    const siteRes = await fetch(
      `https://www.brylliantsolutions.com/form/${ELEMENT_ID}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams(data).toString(),
      }
    );
    if (!siteRes.ok) {
      const html = await siteRes.text();
      console.error("Form post failed:", siteRes.status, html);
      return cors(siteRes.status, "Submission error.");
    }
  } catch (err) {
    console.error("Error posting to site form:", err);
    return cors(500, "Server error. Please try again.");
  }

  // 6) Success
  return cors(200, "OK");
};

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
