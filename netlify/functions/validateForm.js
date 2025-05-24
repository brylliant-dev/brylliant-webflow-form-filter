// netlify/functions/validateForm.js

const blocked       = require("./blocked-domains");
const { resolveMx } = require("dns").promises;

const FORM_ID    = process.env.WEBFLOW_FORM_ID;
const API_TOKEN  = process.env.WEBFLOW_API_TOKEN;
const RC_SECRET  = process.env.RECAPTCHA_SECRET_KEY;

if (!FORM_ID || !API_TOKEN || !RC_SECRET) {
  throw new Error("Missing one of WEBFLOW_FORM_ID, WEBFLOW_API_TOKEN or RECAPTCHA_SECRET_KEY");
}

exports.handler = async (event) => {
  // 1) Parse incoming body
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

  // 4) Block free/disposable domains
  if (!domain || blocked.includes(domain)) {
    return { statusCode: 400, body: "Please use your company email." };
  }

  // 5) Ensure the domain has MX records
  try {
    await resolveMx(domain);
  } catch {
    return { statusCode: 400, body: "Invalid email domain." };
  }

  // 6) Verify reCAPTCHA v3
  const token     = data["g-recaptcha-response"];
  const recaptcha = await fetch(
    `https://www.google.com/recaptcha/api/siteverify?secret=${RC_SECRET}&response=${token}`,
    { method: "POST" }
  ).then(r => r.json());

  if (!recaptcha.success || recaptcha.score < 0.5) {
    return { statusCode: 400, body: "reCAPTCHA verification failed." };
  }

  // 7) Forward to Webflow so that Make can pick it up
  await fetch(`https://api.webflow.com/form/${FORM_ID}`, {
    method: "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${API_TOKEN}`
    },
    body: JSON.stringify(data)
  });

  // 8) Redirect your user
  return {
    statusCode: 302,
    headers:    {
      Location: "https://www.brylliantsolutions.com/free-fix-thank-you"
    }
  };
};
