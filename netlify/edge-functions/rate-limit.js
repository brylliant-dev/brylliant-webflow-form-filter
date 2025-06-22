// netlify/functions/rateLimiter.js

import { getStore } from '@netlify/blobs';

export default async (request) => {
  const ip    = request.headers.get('x-forwarded-for') || 'unknown';
  const store = getStore('rate-limiter');
  const key   = `rate:${ip}`;
  const MAX   = 5;      // max requests
  const WINDOW = 300;   // seconds (5 minutes)

  // 1) fetch current count
  const current = parseInt((await store.get(key)) || '0', 10);
  console.log(`IP ${ip} has made ${current} requests in the last ${WINDOW}s`);

  // 2) if at or above limit, block
  if (current >= MAX) {
    return new Response(
      "Too many requests. Try again in 5 minutes.",
      { status: 429, headers: { "Content-Type": "text/plain" } }
    );
  }

  // 3) otherwise increment & reset TTL
  await store.set(key, String(current + 1), { expirationTtl: WINDOW });

  // 4) allow
  return new Response(
    "Allowed",
    { status: 200, headers: { "Content-Type": "text/plain" } }
  );
};
