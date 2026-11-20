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
  let targetUrl = url.searchParams.get('url') || url.searchParams.get('u');
  if (!targetUrl) {
    const pathname = url.pathname;
    const prefix = '/proxy/';
    const idx = pathname.indexOf(prefix);
    if (idx !== -1) {
      let rest = pathname.slice(idx + prefix.length);
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

  // ── Determine if request is a decryption key or stream chunk ──
  const isKey =
    targetUrl.includes('.key') ||
    targetUrl.includes('.pkey') ||
    targetUrl.includes('getkey') ||
    targetUrl.includes('/key') ||
    Boolean(request.headers.get('channelid')) ||
    Boolean(request.headers.get('channelId')) ||
    Boolean(request.headers.get('ssotoken'));

  // ── Forward request (strip all browser-identifying headers that trigger WAF 403) ──
  const fwdHeaders = new Headers();
  const blockedHeaders = new Set([
    'host', 'origin', 'referer', 'sec-ch-ua', 'sec-ch-ua-mobile',
    'sec-ch-ua-platform', 'sec-ch-ua-model', 'sec-fetch-dest',
    'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
    'accept-encoding', 'accept-language', 'priority',
    'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
    'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip', 'cdn-loop'
  ]);

  for (const [k, v] of request.headers.entries()) {
    const lower = k.toLowerCase();
    if (!blockedHeaders.has(lower) && !lower.startsWith('sec-') && !lower.startsWith('cf-')) {
      fwdHeaders.set(k, v);
    }
  }

  // Set standard ExoPlayer / JioTV App User-Agent
  const jioUa = 'plaYtv/7.1.8 (Linux;Android 13) ExoPlayerLib/1.3.1';
  const incomingUa = fwdHeaders.get('user-agent') || '';
  if (!incomingUa || incomingUa.includes('Mozilla/') || isKey) {
    fwdHeaders.set('User-Agent', jioUa);
  }

  // Akamai Token Cookie Propagation: Extract __hdnea__ or hdnea from URL query or headers
  let hdneaMatch = targetUrl.match(/[?&](?:__hdnea__|hdnea)=([^&]+)/);
  if (!hdneaMatch && request.headers.get('cookie')) {
    hdneaMatch = request.headers.get('cookie').match(/__hdnea__=([^;]+)/);
  }
  if (hdneaMatch && hdneaMatch[1]) {
    const existingCookie = fwdHeaders.get('cookie') || '';
    if (!existingCookie.includes('__hdnea__=')) {
      fwdHeaders.set('Cookie', existingCookie ? `${existingCookie}; __hdnea__=${hdneaMatch[1]}` : `__hdnea__=${hdneaMatch[1]}`);
    }
  }

  // For Jio Key requests, ensure all required authorization headers are present
  if (isKey) {
    if (!fwdHeaders.get('srno')) fwdHeaders.set('srno', '230203144000');
    if (!fwdHeaders.get('appkey')) fwdHeaders.set('appkey', 'NzNiMDhlYzQyNjJm');
    if (!fwdHeaders.get('devicetype')) fwdHeaders.set('devicetype', 'phone');
    if (!fwdHeaders.get('os')) fwdHeaders.set('os', 'android');
    if (!fwdHeaders.get('osVersion')) fwdHeaders.set('osVersion', '13');
    if (!fwdHeaders.get('usergroup')) fwdHeaders.set('usergroup', 'tvYR7NSNn7rymo3F');
    if (!fwdHeaders.get('versionCode') && !fwdHeaders.get('versioncode')) fwdHeaders.set('versionCode', '424');
    if (!fwdHeaders.get('lbcookie')) fwdHeaders.set('lbcookie', '1');
    const chId = fwdHeaders.get('channelid') || fwdHeaders.get('channelId');
    if (chId) {
      fwdHeaders.set('channelId', chId);
      fwdHeaders.set('channelid', chId);
    }
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

  // Read response as ArrayBuffer to prevent stream decoding & content-length desync
  const bodyBuf = await upstream.arrayBuffer();

  const respHeaders = new Headers();
  Object.entries(corsHeaders).forEach(([k, v]) => respHeaders.set(k, v));

  const upstreamType = upstream.headers.get('content-type');
  if (isKey && (bodyBuf.byteLength === 16 || bodyBuf.byteLength === 24 || bodyBuf.byteLength === 32)) {
    respHeaders.set('Content-Type', 'application/octet-stream');
  } else if (upstreamType) {
    respHeaders.set('Content-Type', upstreamType);
  }

  respHeaders.set('Content-Length', String(bodyBuf.byteLength));
  respHeaders.set('Cache-Control', isKey ? 'no-cache, no-store, must-revalidate' : 'public, max-age=6');

  return new Response(bodyBuf, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: respHeaders,
  });
}
