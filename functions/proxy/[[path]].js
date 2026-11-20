/**
 * Cloudflare Pages Function: /proxy/*
 * Handles JioTV API requests, key decryption fetches, and streaming with full CORS support.
 * Automatically runs on your Cloudflare Pages deployment!
 */

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);

  const requestOrigin = request.headers.get('Origin') || '*';
  const corsHeaders = {
    'Access-Control-Allow-Origin': requestOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Expose-Headers': '*',
    'Access-Control-Max-Age': '86400',
  };

  // ── CORS Preflight ──
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // ── Extract target URL ──
  // 1. Check ?url= or ?u= query parameter first (safest against path normalization)
  let targetUrl = url.searchParams.get('url') || url.searchParams.get('u');
  if (!targetUrl) {
    // 2. Fall back to /proxy/<targetUrl> in the pathname
    const pathname = url.pathname;
    const prefix = '/proxy/';
    const idx = pathname.indexOf(prefix);
    if (idx !== -1) {
      let rest = pathname.slice(idx + prefix.length);
      // Restore any collapsed protocol slashes (e.g. https:/jiotvapi -> https://jiotvapi)
      if (rest.startsWith('https:/') && !rest.startsWith('https://')) {
        rest = 'https://' + rest.slice(7);
      } else if (rest.startsWith('http:/') && !rest.startsWith('http://')) {
        rest = 'http://' + rest.slice(6);
      }
      targetUrl = rest + url.search;
    }
  }

  if (!targetUrl) {
    return new Response(
      JSON.stringify({ error: 'Usage: /proxy?url=<target_url>' }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }

  // ── Validate target host ──
  let parsedTarget;
  try {
    parsedTarget = new URL(targetUrl);
  } catch {
    return new Response(
      JSON.stringify({ error: 'Invalid target URL: ' + targetUrl }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }

  if (parsedTarget.protocol !== 'http:' && parsedTarget.protocol !== 'https:') {
    return new Response(
      JSON.stringify({ error: 'Only HTTP/HTTPS URLs are supported' }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }

  const targetHost = parsedTarget.hostname.toLowerCase();
  // Prevent SSRF / local network access
  if (
    targetHost === 'localhost' ||
    targetHost === '127.0.0.1' ||
    targetHost === '0.0.0.0' ||
    targetHost === '::1' ||
    targetHost.startsWith('192.168.') ||
    targetHost.startsWith('10.') ||
    targetHost.startsWith('172.16.') ||
    targetHost === '169.254.169.254'
  ) {
    return new Response(
      JSON.stringify({ error: `Forbidden target host: ${targetHost}` }),
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

  // Ensure Jio-compatible User-Agent for upstream requests if browser UA is sent
  const currentUa = fwdHeaders.get('user-agent') || '';
  if (!currentUa || currentUa.includes('Mozilla/')) {
    fwdHeaders.set('User-Agent', 'plaYtv/7.1.8 (Linux;Android 13) ExoPlayerLib/1.3.1');
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
  respHeaders.delete('content-encoding');

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: respHeaders,
  });
}
