import { getStore } from '@netlify/blobs';

export default async (request) => {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  const store = getStore('rate-limiter');
  const key = `rate:${ip}`;

  const current = parseInt((await store.get(key)) || '0');

  if (current >= 5) {
    return new Response("Too many requests from this IP. Try again in 5 minutes.", {
      status: 429,
      headers: { "Content-Type": "text/plain" },
    });
  }

  await store.set(key, String(current + 1), { expirationTtl: 300 }); // TTL = 5 minutes

  return new Response("Allowed", {
    status: 200,
    headers: { "Content-Type": "text/plain" },
  });
};
