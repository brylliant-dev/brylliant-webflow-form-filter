// netlify/functions/validateForm.js

const blocked       = require("./blocked-domains");
const { resolveMx } = require("dns").promises;

const FORM_ID   = process.env.WEBFLOW_FORM_ID;
const API_TOKEN = process.env.WEBFLOW_API_TOKEN;

if (!FORM_ID || !API_TOKEN) {
  throw new Error("Missing WEBFLOW_FORM_ID or WEBFLOW_API_TOKEN env var");
}

exports.handler = async (event) => {
  // 1) Parse JSON or x-www-form-urlencoded
  const ct   = (event.headers["content-type"] || "").toLowerCase();
  const data = ct.includes("application/json")
    ? JSON.parse(event.body || "{}")
    : Object.fromEntries(new URLSearchParams(event.body));

  // 2) Normalize email
  const rawEmail = (data.email ?? data.Email ?? "").trim();
  const email    = rawEmail.toLowerCase();
  const domain   = email.split("@")[1] || "";

  // 3) Honeypot
  if (data.hp_name) {
    return { statusCode: 400, body: "Bot detected." };
  }

  // 4) Block common free/disposable domains
  if (!domain || blocked.includes(domain)) {
    return { statusCode: 400, body: "Please use your company email." };
  }

  // 5) MX-record lookup
  try {
    await resolveMx(domain);
  } catch {
    return { statusCode: 400, body: "Invalid email domain." };
  }

  // 6) Forward to Webflow (so Make’s Webflow watcher will see it)
  await fetch(`https://api.webflow.com/form/${FORM_ID}`, {
    method: "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${API_TOKEN}`
    },
    body: JSON.stringify(data)
  });

  // 7) Redirect to your Thank You page
  return {
    statusCode: 302,
    headers: {
      Location: "https://www.brylliantsolutions.com/free-fix-thank-you"
    }
  };
};
