const DEFAULT_DOH_PATH = "dns-query";
const DEFAULT_UPSTREAMS = [
  "https://dns.google/dns-query",
  "https://cloudflare-dns.com/dns-query",
  "https://dns.quad9.net/dns-query",
];

function normalizeHostname(value) {
  return String(value || "").trim().toLowerCase().replace(/\.$/, "");
}

function normalizePath(pathname) {
  return String(pathname || "/").replace(/^\/+|\/+$/g, "") || DEFAULT_DOH_PATH;
}

function getUpstreams(env) {
  const raw = env.UPSTREAM_URLS || DEFAULT_UPSTREAMS.join(",");
  return raw
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean)
    .map((v) => (v.endsWith("/") ? v.slice(0, -1) : v));
}

function buildBlockResponse(name, type, mode, request) {
  const responseType = request.headers.get("accept") || "";
  const qtype = Number(type || 1) || 1;
  const recordName = normalizeHostname(name) || "";
  const isJson = responseType.includes("application/dns-json") || responseType.includes("application/json");

  if (mode === "null") {
    const answerData = qtype === 28 ? "::" : "0.0.0.0";
    const payload = {
      Status: 0,
      TC: false,
      RD: true,
      RA: true,
      AD: false,
      CD: false,
      Question: [{ name: recordName, type: qtype }],
      Answer: [{ name: recordName, type: qtype, TTL: 0, data: answerData }],
    };
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "content-type": isJson ? "application/dns-json" : "application/json" },
    });
  }

  const payload = {
    Status: 3,
    TC: false,
    RD: true,
    RA: true,
    AD: false,
    CD: false,
    Question: [{ name: recordName, type: qtype }],
    Answer: [],
  };

  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "content-type": isJson ? "application/dns-json" : "application/json" },
  });
}

function buildCacheKey(url, params) {
  const key = `${url.pathname}?${params.toString()}`;
  return new Request(`https://cache.internal/${encodeURIComponent(key)}`);
}

async function handleBlockDecision(request, env, url) {
  const nameParam = url.searchParams.get("name");
  const qtype = url.searchParams.get("type") || "A";
  const blockMode = (env.BLOCK_MODE || "nxdomain").toLowerCase();

  if (!nameParam || !env.BLOCKLIST && !env.ALLOWLIST) {
    return null;
  }

  const domain = normalizeHostname(nameParam);
  const allowKey = domain ? await env.ALLOWLIST?.get(domain) : null;
  if (allowKey !== null && allowKey !== undefined) {
    return null;
  }

  const blockKey = domain ? await env.BLOCKLIST?.get(domain) : null;
  if (blockKey !== null && blockKey !== undefined) {
    return buildBlockResponse(domain, qtype, blockMode, request);
  }

  if (env.ALLOWLIST) {
    const allowlistExists = await env.ALLOWLIST.get("__enabled__");
    if (allowlistExists && allowlistExists === "1") {
      const target = domain;
      const allowValue = await env.ALLOWLIST.get(target);
      if (!allowValue) {
        return buildBlockResponse(domain, qtype, blockMode, request);
      }
    }
  }

  return null;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const expectedPath = normalizePath(env.DOH_PATH || DEFAULT_DOH_PATH);
    const requestPath = normalizePath(url.pathname);

    if (requestPath !== expectedPath) {
      return new Response("Not found", { status: 404 });
    }

    const upstreams = getUpstreams(env);
    if (!upstreams.length) {
      return new Response("No upstream DNS resolvers configured", { status: 500 });
    }

    const blockedResponse = await handleBlockDecision(request, env, url);
    if (blockedResponse) {
      return blockedResponse;
    }

    const method = request.method.toUpperCase();
    const acceptHeader = request.headers.get("accept") || "";
    const passedHeaders = new Headers(request.headers);
    passedHeaders.set("host", new URL(upstreams[0]).host);
    passedHeaders.delete("content-length");

    const upstreamUrl = upstreams[Math.floor(Math.random() * upstreams.length)];
    const body = method === "POST" ? await request.arrayBuffer() : null;

    try {
      const cacheKey = buildCacheKey(url, url.searchParams);
      const cached = await caches.default.match(cacheKey);
      if (cached) {
        return cached;
      }

      const upstreamRequest = new Request(upstreamUrl, {
        method,
        headers: passedHeaders,
        body: body ? body : undefined,
      });

      const response = await fetch(upstreamRequest);
      const responseClone = response.clone();

      const responseHeaders = new Headers(response.headers);
      const cacheable = response.status === 200 && acceptHeader.includes("application/dns-json") || acceptHeader.includes("application/json") || acceptHeader.includes("application/dns-message");

      if (cacheable) {
        ctx.waitUntil(caches.default.put(cacheKey, responseClone));
      }

      return response;
    } catch (error) {
      return new Response(JSON.stringify({ error: String(error) }), {
        status: 502,
        headers: { "content-type": "application/json" },
      });
    }
  },
};
