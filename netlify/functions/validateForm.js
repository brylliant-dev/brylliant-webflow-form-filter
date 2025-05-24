const blocked = require("./blocked-domains");
const dns     = require("dns").promises;
const fetch   = require("node-fetch");

const FORM_ID    = process.env.WEBFLOW_FORM_ID;
const API_TOKEN  = process.env.WEBFLOW_API_TOKEN;
const RC_SECRET  = process.env.RECAPTCHA_SECRET_KEY;

exports.handler = async (event) => {
  const data  = JSON.parse(event.body || "{}");
  const email = (data.email || "").trim().toLowerCase();
  const domain= email.split("@")[1] || "";

  // 1) Honeypot
  if (data.hp_name) {
    return { statusCode: 400, body: "Bot detected." };
  }

  // 2) Blocked-domain check
  if (!domain || blocked.includes(domain)) {
    return { statusCode: 400, body: "Please use your company email." };
  }

  // 3) MX-record lookup
  try {
    await dns.resolveMx(domain);
  } catch {
    return { statusCode: 400, body: "Invalid email domain." };
  }

  // 4) Verify reCAPTCHA v3
  const token = data["g-recaptcha-response"];
  const rcRes = await fetch(
    `https://www.google.com/recaptcha/api/siteverify?secret=${RC_SECRET}&response=${token}`,
    { method: "POST" }
  ).then(res => res.json());

  if (!rcRes.success || rcRes.score < 0.5) {
    return { statusCode: 400, body: "reCAPTCHA verification failed." };
  }

  // 5) Forward to Webflow
  await fetch(`https://api.webflow.com/form/${FORM_ID}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_TOKEN}`
    },
    body: JSON.stringify(data)
  });

  return { statusCode: 200, body: "OK" };
};
