// netlify/functions/validateForm.js

const blocked      = require("./blocked-domains");
const { resolveMx } = require("dns").promises;

// Pull in your secrets
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET_KEY;
const WEBHOOK_URL      = process.env.MAKE_WEBHOOK_URL;

// Fail hard if one of these is missing
if (!RECAPTCHA_SECRET || !WEBHOOK_URL) {
  throw new Error(
    "Missing one of RECAPTCHA_SECRET_KEY or MAKE_WEBHOOK_URL in your env vars"
  );
}

exports.handler = async (event) => {
  // 1) Parse JSON or form-encoded body
  const ct   = (event.headers["content-type"] || "").toLowerCase();
  const data = ct.includes("application/json")
    ? JSON.parse(event.body || "{}")
    : Object.fromEntries(new URLSearchParams(event.body));

  // 2) Grab the email (either key), trim & lowercase for checks
  const rawEmail = (data.email ?? data.Email ?? "").trim();
  const email    = rawEmail.toLowerCase();
  const domain   = email.split("@")[1] || "";

  // 3) Honeypot: reject bots
  if (data.hp_name) {
    return { statusCode: 400, body: "Bot detected." };
  }

  // 4) Block common free/disposable domains
  if (!domain || blocked.includes(domain)) {
    return { statusCode: 400, body: "Please use your company email." };
  }

  // 5) MX lookup to ensure the domain can receive mail
  try {
    await resolveMx(domain);
  } catch {
    return { statusCode: 400, body: "Invalid email domain." };
  }

  // 6) Verify reCAPTCHA v3
  const token     = data["g-recaptcha-response"];
  const recaptcha = await fetch(
    `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET}&response=${token}`,
    { method: "POST" }
  ).then(r => r.json());

  if (!recaptcha.success || recaptcha.score < 0.5) {
    return { statusCode: 400, body: "reCAPTCHA verification failed." };
  }

  // 7) Fire your Make webhook with all form fields
  await fetch(WEBHOOK_URL, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      email:      rawEmail,
      name:       data.Name,
      websiteUrl: data["Website-URL"],
      issue:      data["Site-Issue"],
      consent:    data["I-agree-to-be-contacted-by-Brylliant-Solutions"],
      turnstile:  data["cf-turnstile-response"]
    })
  });

  // 8) Redirect to your public Thank You page
  return {
    statusCode: 302,
    headers:    {
      Location: "https://www.brylliantsolutions.com/free-fix-thank-you"
    }
  };
};
