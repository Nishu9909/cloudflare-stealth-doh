const DNS_MSG = 'application/dns-message';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const dohPath = env.DOH_PATH || 'dns-query';

    if (url.pathname !== `/${dohPath}`) {
      return new Response('Not Found', { status: 404 });
    }

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
  const cacheKey = new Request(request.url, { method: 'GET' });
  const cache = caches.default;
  let response = await cache.match(cacheKey);

  if (!response) {
    const upstreams = (env.UPSTREAM_URLS || 'https://dns.google/dns-query,https://cloudflare-dns.com/dns-query').split(',');
    const headers = new Headers({ 'Content-Type': DNS_MSG, 'Accept': DNS_MSG });

    // --- ECS INJECTION LOGIC ---
    const clientIp = request.headers.get('2a09:bac1:36a0:58::2fe:32');
    if (clientIp) {
      const ecsSubnet = maskIpForECS(clientIp);
      if (ecsSubnet) {
        // Google DNS uses X-Forwarded-For to read ECS data
        headers.set('X-Forwarded-For', ecsSubnet);
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
      response = await Promise.any(promises);
      const ttl = parseInt(env.CACHE_TTL || '300', 10);
      const cached = new Response(response.body, response);
      cached.headers.set('Cache-Control', `public, max-age=${ttl}`);
      ctx.waitUntil(cache.put(cacheKey, cached.clone()));
      response = cached;
    } catch (e) {
      return new Response('All Upstreams Failed', { status: 502 });
    }
  }

  return new Response(response.body, {
    headers: {
      'Content-Type': DNS_MSG,
      'Access-Control-Allow-Origin': '*'
    }
  });
}

// --- Helper: Mask IP for ECS (IPv4 /24, IPv6 /56) ---
function maskIpForECS(ip) {
  if (ip.includes(':')) {
    // IPv6: keep first 3.5 hextets (56 bits)
    const parts = ip.split(':');
    if (parts.length >= 4) {
      return `${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}::/56`;
    }
  } else {
    // IPv4: keep first 3 octets
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }
  }
  return null;
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}