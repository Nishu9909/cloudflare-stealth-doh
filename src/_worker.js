const DNS_MSG = 'application/dns-message';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Stealth path check
    const dohPath = env.DOH_PATH || 'dns-query';
    if (url.pathname !== `/${dohPath}`) {
      return new Response('Not Found', { status: 404 });
    }

    // Handle GET (base64url) or POST (binary)
    if (request.method === 'GET') {
      const dns = url.searchParams.get('dns');
      if (!dns) return new Response('Bad Request', { status: 400 });
      return handleDnsQuery(base64ToArrayBuffer(dns), request, env, ctx);
    } 
    
    if (request.method === 'POST' && request.headers.get('content-type') === DNS_MSG) {
      const buf = await request.arrayBuffer();
      return handleDnsQuery(buf, request, env, ctx);
    }

    return new Response('Unsupported Media Type', { status: 415 });
  }
};

async function handleDnsQuery(dnsBuffer, request, env, ctx) {
  // 1. Check Edge Cache
  const cacheKey = new Request(request.url, { method: 'GET' });
  const cache = caches.default;
  let response = await cache.match(cacheKey);

  if (!response) {
    // 2. Parallel Upstream Racing
    const upstreams = (env.UPSTREAM_URLS || 'https://dns.google/dns-query,https://cloudflare-dns.com/dns-query').split(',');
    
    // Build headers (ECS support)
    const headers = new Headers({ 'Content-Type': DNS_MSG, 'Accept': DNS_MSG });
    const clientIp = request.headers.get('CF-Connecting-IP');
    
    if (clientIp && env.ENABLE_ECS === 'true') {
      // Simple ECS masking for IPv4 (Google DNS supports this)
      if (clientIp.includes('.') && !clientIp.includes(':')) {
        const parts = clientIp.split('.');
        headers.set('X-Forwarded-For', `${parts[0]}.${parts[1]}.${parts[2]}.0`);
      }
    }

    const promises = upstreams.map(u =>
      fetch(u, { method: 'POST', headers, body: dnsBuffer })
        .then(r => {
          if (!r.ok) throw new Error(`Upstream ${u} failed: ${r.status}`);
          return r;
        })
    );

    try {
      // Use Promise.any to grab the fastest successful response
      response = await Promise.any(promises);
      
      // 3. Cache the result
      const ttl = parseInt(env.CACHE_TTL || '300', 10);
      const cached = new Response(response.body, response);
      cached.headers.set('Cache-Control', `public, max-age=${ttl}`);
      ctx.waitUntil(cache.put(cacheKey, cached.clone()));
      
      response = cached;
    } catch (e) {
      return new Response('All Upstreams Failed', { status: 502 });
    }
  }

  // 4. Return to client
  return new Response(response.body, {
    headers: {
      'Content-Type': DNS_MSG,
      'Access-Control-Allow-Origin': '*'
    }
  });
}

// Helper: Base64URL to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binary = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
