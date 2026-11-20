/**
 * JioTV CORS Proxy — Cloudflare Worker
 * Routes browser requests to JioTV API endpoints, adding CORS headers.
 * Allowed origin: https://balram2020.github.io
 */

const ALLOWED_ORIGIN = 'https://balram2020.github.io';

const JIO_ALLOWED_HOSTS = [
  'jiotvapi.media.jio.com',
  'jiotvapi.cdn.jio.com',
  'auth.media.jio.com',
  'tv.media.jio.com',
];

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Max-Age': '86400',
};

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // ── CORS Preflight ──
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // ── Parse target URL from path: /proxy/<target_url> ──
    // e.g. /proxy/https://jiotvapi.media.jio.com/userservice/apis/v1.3/validateMobile/sendOTP
    const rawPath = url.pathname.slice(1); // strip leading /
    const proxyPrefix = 'proxy/';
    if (!rawPath.startsWith(proxyPrefix)) {
      return new Response(
        JSON.stringify({ error: 'Usage: /proxy/<jiotv-api-url>' }),
        { status: 400, headers: { 'Content-Type': 'application/json', ...CORS_HEADERS } }
      );
    }

    const targetUrl = rawPath.slice(proxyPrefix.length) + url.search;

    // ── Validate target host ──
    let targetHost;
    try {
      targetHost = new URL(targetUrl).hostname;
    } catch {
      return new Response(
        JSON.stringify({ error: 'Invalid target URL' }),
        { status: 400, headers: { 'Content-Type': 'application/json', ...CORS_HEADERS } }
      );
    }

    if (!JIO_ALLOWED_HOSTS.some(h => targetHost === h || targetHost.endsWith('.' + h))) {
      return new Response(
        JSON.stringify({ error: `Forbidden host: ${targetHost}` }),
        { status: 403, headers: { 'Content-Type': 'application/json', ...CORS_HEADERS } }
      );
    }

    // ── Build forwarded request (strip browser-added headers) ──
    const fwdHeaders = new Headers();
    const skipHeaders = new Set(['host', 'origin', 'referer', 'cf-connecting-ip',
      'cf-ipcountry', 'cf-ray', 'cf-visitor', 'x-forwarded-for', 'x-real-ip']);
    for (const [k, v] of request.headers.entries()) {
      if (!skipHeaders.has(k.toLowerCase())) fwdHeaders.set(k, v);
    }

    const fwdInit = {
      method: request.method,
      headers: fwdHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : null,
      redirect: 'follow',
    };

    // ── Proxy the request ──
    let upstream;
    try {
      upstream = await fetch(targetUrl, fwdInit);
    } catch (e) {
      return new Response(
        JSON.stringify({ error: 'Upstream fetch failed', detail: e.message }),
        { status: 502, headers: { 'Content-Type': 'application/json', ...CORS_HEADERS } }
      );
    }

    // ── Return response with CORS headers ──
    const respHeaders = new Headers(upstream.headers);
    Object.entries(CORS_HEADERS).forEach(([k, v]) => respHeaders.set(k, v));
    // Remove headers that conflict with CORS
    respHeaders.delete('x-frame-options');
    respHeaders.delete('content-security-policy');

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: respHeaders,
    });
  },
};
