const DNS_MESSAGE = "application/dns-message";
const MAX_DNS_MESSAGE_SIZE = 65_535;
const DEFAULT_UPSTREAMS = [
  "https://dns.google/dns-query",
  "https://cloudflare-dns.com/dns-query",
];

function getPath(env) {
  const configured = String(env.DOH_PATH || "dns-query").trim();
  return `/${configured.replace(/^\/+|\/+$/g, "") || "dns-query"}`;
}

function getUpstreams(env) {
  const configured = String(env.UPSTREAM_URLS || DEFAULT_UPSTREAMS.join(","));
  return configured
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
    .slice(0, 5)
    .filter((value) => {
      try {
        return new URL(value).protocol === "https:";
      } catch {
        return false;
      }
    });
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept",
    "Access-Control-Max-Age": "86400",
  };
}

function httpError(message, status) {
  return new Response(message, {
    status,
    headers: { ...corsHeaders(), "Cache-Control": "no-store" },
  });
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) return null;
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function parseQuestion(message) {
  if (message.length < 17 || message.length > MAX_DNS_MESSAGE_SIZE) return null;
  const view = new DataView(message.buffer, message.byteOffset, message.byteLength);
  if (view.getUint16(4, false) !== 1) return null;

  const labels = [];
  let offset = 12;
  let totalNameLength = 0;
  while (offset < message.length) {
    const length = message[offset++];
    if (length === 0) break;
    // Queries should carry an uncompressed QNAME. Reject pointers and invalid labels.
    if ((length & 0xc0) !== 0 || length > 63 || offset + length > message.length) return null;
    const labelBytes = message.subarray(offset, offset + length);
    if (labelBytes.some((byte) => byte > 127)) return null;
    labels.push(String.fromCharCode(...labelBytes));
    offset += length;
    totalNameLength += length + 1;
    if (totalNameLength > 255) return null;
  }

  if (offset + 4 > message.length || labels.length === 0) return null;
  const questionEnd = offset + 4;
  const qtype = view.getUint16(offset, false);
  const qclass = view.getUint16(offset + 2, false);
  if (qclass !== 1) return null;

  return {
    name: labels.join(".").toLowerCase().replace(/\.$/, ""),
    qtype,
    questionEnd,
  };
}

function getDomainCandidates(domain) {
  const labels = domain.split(".");
  const candidates = [];
  for (let i = 0; i < labels.length; i++) candidates.push(labels.slice(i).join("."));
  return candidates;
}

async function hasKvMatch(namespace, candidates) {
  if (!namespace) return false;
  for (const candidate of candidates) {
    const value = await namespace.get(candidate);
    if (value !== null && value !== undefined) return true;
  }
  return false;
}

async function shouldBlock(domain, env) {
  if (env.ALLOWLIST && (await hasKvMatch(env.ALLOWLIST, getDomainCandidates(domain)))) return false;

  const allowlistOnly = env.ALLOWLIST
    ? await env.ALLOWLIST.get("__enabled__")
    : null;
  if (allowlistOnly === "1") return true;

  return hasKvMatch(env.BLOCKLIST, getDomainCandidates(domain));
}

function makeDnsResponse(query, question, rcode, answer = null) {
  const questionBytes = query.subarray(12, question.questionEnd);
  const answerLength = answer ? answer.length : 0;
  const output = new Uint8Array(12 + questionBytes.length + answerLength);
  output.set(query.subarray(0, 2), 0);
  output.set(questionBytes, 12);

  const queryFlags = (query[2] << 8) | query[3];
  const flags = 0x8000 | (queryFlags & 0x0100) | (queryFlags & 0x0010) | 0x0080 | rcode;
  const view = new DataView(output.buffer);
  view.setUint16(2, flags, false);
  view.setUint16(4, 1, false);
  view.setUint16(6, answer ? 1 : 0, false);
  view.setUint16(8, 0, false);
  view.setUint16(10, 0, false);
  if (answer) output.set(answer, 12 + questionBytes.length);
  return new Response(output, {
    status: 200,
    headers: {
      ...corsHeaders(),
      "Content-Type": DNS_MESSAGE,
      "Cache-Control": "no-store",
    },
  });
}

function makeBlockedResponse(query, question, mode) {
  if (mode === "null" && (question.qtype === 1 || question.qtype === 28)) {
    const rdata = question.qtype === 1
      ? new Uint8Array([0, 0, 0, 0])
      : new Uint8Array(16);
    const answer = new Uint8Array(12 + rdata.length);
    const view = new DataView(answer.buffer);
    view.setUint16(0, 0xc00c, false); // Name pointer to the question name.
    view.setUint16(2, question.qtype, false);
    view.setUint16(4, 1, false); // IN
    view.setUint32(6, 0, false); // TTL 0
    view.setUint16(10, rdata.length, false);
    answer.set(rdata, 12);
    return makeDnsResponse(query, question, 0, answer);
  }

  if (mode === "refused") return makeDnsResponse(query, question, 5);
  return makeDnsResponse(query, question, 3); // NXDOMAIN
}

function makeCacheKey(url, query) {
  // Avoid caching unusually large queries to keep custom cache keys bounded.
  if (query.length > 4096) return null;
  const encoded = encodeBase64Url(query);
  return new Request(`https://dns-cache.invalid${url.pathname}?q=${encoded}`);
}

async function fetchFromUpstreams(query, upstreams) {
  const attempts = upstreams.map(async (upstream) => {
    const response = await fetch(upstream, {
      method: "POST",
      headers: { "Content-Type": DNS_MESSAGE, Accept: DNS_MESSAGE },
      body: query,
      redirect: "error",
    });
    if (!response.ok) throw new Error(`Upstream returned HTTP ${response.status}`);
    const contentType = (response.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    if (contentType !== DNS_MESSAGE) throw new Error("Upstream returned an unexpected content type");
    return response;
  });
  return Promise.any(attempts);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname !== getPath(env)) return httpError("Not found", 404);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    let query;
    if (request.method === "GET") {
      const encoded = url.searchParams.get("dns");
      if (!encoded) return httpError("Missing dns parameter", 400);
      query = decodeBase64Url(encoded);
      if (!query) return httpError("Invalid DNS message encoding", 400);
    } else if (request.method === "POST") {
      const contentType = (request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
      if (contentType !== DNS_MESSAGE) return httpError("Expected application/dns-message", 415);
      if (Number(request.headers.get("content-length") || 0) > MAX_DNS_MESSAGE_SIZE) {
        return httpError("DNS message too large", 413);
      }
      query = new Uint8Array(await request.arrayBuffer());
    } else {
      return httpError("Method not allowed", 405);
    }

    if (query.length > MAX_DNS_MESSAGE_SIZE) return httpError("DNS message too large", 413);
    const question = parseQuestion(query);
    if (!question) return httpError("Malformed or unsupported DNS query", 400);

    if (await shouldBlock(question.name, env)) {
      const mode = String(env.BLOCK_MODE || "nxdomain").toLowerCase();
      return makeBlockedResponse(query, question, mode);
    }

    const upstreams = getUpstreams(env);
    if (upstreams.length === 0) return httpError("No valid HTTPS upstreams configured", 500);

    const cache = caches.default;
    const cacheKey = makeCacheKey(url, query);
    const configuredTtl = Number.parseInt(env.CACHE_TTL || "0", 10);
    const cacheTtl = Number.isFinite(configuredTtl) ? Math.min(Math.max(configuredTtl, 0), 3600) : 0;
    let response = cacheKey && cacheTtl > 0 ? await cache.match(cacheKey) : null;

    if (!response) {
      try {
        response = await fetchFromUpstreams(query, upstreams);
        const body = await response.arrayBuffer();
        if (body.byteLength > MAX_DNS_MESSAGE_SIZE) return httpError("Upstream DNS response too large", 502);
        const responseHeaders = new Headers(corsHeaders());
        responseHeaders.set("Content-Type", DNS_MESSAGE);
        responseHeaders.set("Cache-Control", cacheKey && cacheTtl > 0 ? `public, max-age=${cacheTtl}` : "no-store");
        const result = new Response(body, { status: 200, headers: responseHeaders });
        if (cacheKey && cacheTtl > 0) ctx.waitUntil(cache.put(cacheKey, result.clone()));
        return result;
      } catch {
        return httpError("All DNS upstreams failed", 502);
      }
    }

    const headers = new Headers(response.headers);
    for (const [name, value] of Object.entries(corsHeaders())) headers.set(name, value);
    headers.set("Content-Type", DNS_MESSAGE);
    return new Response(response.body, { status: response.status, headers });
  },
};
