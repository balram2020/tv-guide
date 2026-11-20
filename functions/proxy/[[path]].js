/**
 * Cloudflare Pages Function: /proxy/*
 * Handles JioTV API requests with full CORS support.
 * Automatically runs on your Cloudflare Pages deployment!
 */

const JIO_ALLOWED_HOSTS = [
  'jiotvapi.media.jio.com',
  'jiotvapi.cdn.jio.com',
  'auth.media.jio.com',
  'tv.media.jio.com',
];

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);

  const requestOrigin = request.headers.get('Origin') || '*';
  const corsHeaders = {
    'Access-Control-Allow-Origin': requestOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Max-Age': '86400',
  };

  // ── CORS Preflight ──
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // ── Extract target URL from path: /proxy/<target_url> ──
  const pathname = url.pathname;
  const prefix = '/proxy/';
  const idx = pathname.indexOf(prefix);
  if (idx === -1) {
    return new Response(
      JSON.stringify({ error: 'Usage: /proxy/<jiotv-api-url>' }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }

  const targetUrl = pathname.slice(idx + prefix.length) + url.search;

  // ── Validate target host ──
  let targetHost;
  try {
    targetHost = new URL(targetUrl).hostname;
  } catch {
    return new Response(
      JSON.stringify({ error: 'Invalid target URL: ' + targetUrl }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }

  if (!JIO_ALLOWED_HOSTS.some(h => targetHost === h || targetHost.endsWith('.' + h))) {
    return new Response(
      JSON.stringify({ error: `Forbidden host: ${targetHost}` }),
      { status: 403, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }

  // ── Forward request (strip browser-injected headers) ──
  const fwdHeaders = new Headers();
  const skipHeaders = new Set([
    'host', 'origin', 'referer', 'cf-connecting-ip',
    'cf-ipcountry', 'cf-ray', 'cf-visitor', 'x-forwarded-for', 'x-real-ip'
  ]);
  for (const [k, v] of request.headers.entries()) {
    if (!skipHeaders.has(k.toLowerCase())) fwdHeaders.set(k, v);
  }

  const fwdInit = {
    method: request.method,
    headers: fwdHeaders,
    body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : null,
    redirect: 'follow',
  };

  // ── Execute upstream fetch ──
  let upstream;
  try {
    upstream = await fetch(targetUrl, fwdInit);
  } catch (e) {
    return new Response(
      JSON.stringify({ error: 'Upstream fetch failed', detail: e.message }),
      { status: 502, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }

  // ── Return response with CORS headers ──
  const respHeaders = new Headers(upstream.headers);
  Object.entries(corsHeaders).forEach(([k, v]) => respHeaders.set(k, v));
  respHeaders.delete('x-frame-options');
  respHeaders.delete('content-security-policy');

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: respHeaders,
  });
}
