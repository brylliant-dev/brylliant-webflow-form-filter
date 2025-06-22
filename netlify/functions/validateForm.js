// netlify/functions/validateForm.js

import { getStore }         from '@netlify/blobs';
const blocked               = require("./blocked-domains");
const disposableDomains     = require("disposable-email-domains");
const { parse }             = require("tldts");
const { resolveMx }         = require("dns").promises;

const FORM_ID   = process.env.WEBFLOW_FORM_ID;
const API_TOKEN = process.env.WEBFLOW_API_TOKEN;
if (!FORM_ID || !API_TOKEN) {
  throw new Error("Missing WEBFLOW_FORM_ID or WEBFLOW_API_TOKEN");
}

// Rate-limit constants
const MAX    = 5;      // max submissions
const WINDOW = 300;    // seconds

exports.handler = async (event) => {
  // --- CORS preflight ---
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin":   "*",
        "Access-Control-Allow-Methods":  "POST,OPTIONS",
        "Access-Control-Allow-Headers":  "Content-Type",
      },
    };
  }

  // --- RATE LIMITING ---
  const ip    = event.headers["x-forwarded-for"] || "unknown";
  const store = getStore("rate-limiter");
  const key   = `rate:${ip}`;
  const raw   = await store.get(key);
  const current = parseInt(raw || "0", 10);

  if (current >= MAX) {
    return cors(429, "Too many requests. Try again in 5 minutes.");
  }
  // increment + reset TTL
  await store.set(key, String(current + 1), { expirationTtl: WINDOW });

  // --- BODY PARSING ---
  const ct   = (event.headers["content-type"] || "").toLowerCase();
  const data = ct.includes("application/json")
    ? JSON.parse(event.body || "{}")
    : Object.fromEntries(new URLSearchParams(event.body));

  // --- EMAIL VALIDATION ---
  const rawEmail   = (data.email || data.Email || "").trim();
  const email      = rawEmail.toLowerCase();
  const domain     = email.split("@")[1] || "";
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

  // 3) MX check
  try {
    await resolveMx(domain);
  } catch {
    return cors(400, "Invalid email domain.");
  }

  // --- FORWARD TO WEBFLOW ---
  try {
    const wfRes = await fetch(`https://api.webflow.com/form/${FORM_ID}`, {
      method: "POST",
      headers: {
        "Content-Type":   "application/json",
        "Authorization":   `Bearer ${API_TOKEN}`,
        "accept-version":  "1.0.0",
      },
      body: JSON.stringify(data),
    });
    const text = await wfRes.text();
    console.log("Webflow API:", wfRes.status, text);
    if (!wfRes.ok) {
      return cors(wfRes.status, `Webflow error: ${text}`);
    }
  } catch (err) {
    console.error("Webflow forward error:", err);
    return cors(500, "Server error. Please try again.");
  }

  // --- SUCCESS ---
  return cors(200, "OK");
};

// helper to add CORS + plain-text body
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
