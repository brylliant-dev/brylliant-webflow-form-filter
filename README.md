# Brylliant Webflow Form Filter

## Setup

1. `npm install`
2. Copy `.env.example` → `.env` and fill in your keys.
3. `npx netlify dev` to test locally.
4. `npx netlify deploy --prod` to push live.

## Workflow

- Your Webflow form’s **Action URL** →  
  `https://<your-site>.netlify.app/.netlify/functions/validateForm`
- Remember to add the honeypot `<input name="hp_name">` and your reCAPTCHA embed in Webflow.
