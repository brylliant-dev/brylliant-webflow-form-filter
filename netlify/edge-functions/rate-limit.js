import { getStore } from '@netlify/blobs';

export default async (request) => {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  const store = getStore('rate-limiter');
  const key = `rate:${ip}`;

  const currentRaw = await store.get(key);
  const current = parseInt(currentRaw || '0');

  if (current >= 5) {
    return new Response("Too many requests from this IP. Try again in 5 minutes.", {
      status: 429,
      headers: { "Content-Type": "text/plain" },
    });
  }

  // Only set TTL when the key is new
  if (!currentRaw) {
    await store.set(key, '1', { expirationTtl: 300 });
  } else {
    await store.set(key, String(current + 1)); // No TTL = use original expiry
  }

  return new Response("Allowed", {
    status: 200,
    headers: { "Content-Type": "text/plain" },
  });
};
