/**
 * JioTV CORS Proxy — Cloudflare Worker
 * Routes browser requests to JioTV API endpoints and streams, adding CORS headers.
 */

export default {
  async fetch(request) {
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

    // ── Extract target URL (supports query param ?url= or path-based /proxy/https://... or /https://...) ──
    let targetUrl = url.searchParams.get('url') || url.searchParams.get('u');
    if (!targetUrl) {
      let pathname = url.pathname;
      if (pathname.startsWith('/proxy/')) pathname = pathname.slice(7);
      else if (pathname.startsWith('/proxy')) pathname = pathname.slice(6);
      else if (pathname.startsWith('/')) pathname = pathname.slice(1);

      if (pathname.startsWith('https:/') && !pathname.startsWith('https://')) {
        pathname = 'https://' + pathname.slice(7);
      } else if (pathname.startsWith('http:/') && !pathname.startsWith('http://')) {
        pathname = 'http://' + pathname.slice(6);
      }
      if (pathname.startsWith('http://') || pathname.startsWith('https://')) {
        targetUrl = pathname + url.search;
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
      targetHost.startsWith('172.17.') ||
      targetHost.startsWith('172.18.') ||
      targetHost.startsWith('172.19.') ||
      targetHost.startsWith('172.2') ||
      targetHost.startsWith('172.3') ||
      targetHost === '169.254.169.254'
    ) {
      return new Response(
        JSON.stringify({ error: `Forbidden target host: ${targetHost}` }),
        { status: 403, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
      );
    }

    const isJioTarget =
      targetHost.includes('jio') ||
      targetHost.includes('jiotv') ||
      targetHost.includes('akamaized.net') ||
      targetHost.includes('n18syndication');
    const hasJioAuth = Boolean(request.headers.get('ssotoken')) || Boolean(request.headers.get('accesstoken'));
    const isKey =
      targetUrl.includes('.key') ||
      targetUrl.includes('.pkey') ||
      targetUrl.includes('getkey') ||
      targetUrl.includes('/key') ||
      Boolean(request.headers.get('channelid')) ||
      Boolean(request.headers.get('channelId')) ||
      Boolean(request.headers.get('channel_id')) ||
      hasJioAuth;

    // ── Forward request (strip browser WAF-triggering headers) ──
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
    if (!incomingUa || incomingUa.includes('Mozilla/') || isKey || isJioTarget) {
      fwdHeaders.set('User-Agent', jioUa);
    }

    // Network18 syndication / Akamai referer fallback
    if (targetHost.includes('n18syndication') || targetHost.includes('akamaized.net')) {
      if (!fwdHeaders.has('referer')) {
        fwdHeaders.set('Referer', 'https://www.cnbctv18.com/');
      }
    }

    // Extract query parameters from target URL
    const searchParams = parsedTarget.searchParams;
    const urlChannelId = searchParams.get('channelid') || searchParams.get('channel_id') || searchParams.get('channelId');
    const urlSrno = searchParams.get('srno');
    const hdneaVal = searchParams.get('__hdnea__') || searchParams.get('hdnea');

    // Build cookies (propagating query params, hdnea, and Jio auth matching JioTV-Go key handling)
    const existingCookie = fwdHeaders.get('cookie') || '';
    const cookiePairs = existingCookie ? existingCookie.split(';').map(s => s.trim()).filter(Boolean) : [];
    const cookieMap = new Map();
    for (const pair of cookiePairs) {
      const eqIdx = pair.indexOf('=');
      if (eqIdx !== -1) cookieMap.set(pair.slice(0, eqIdx).trim(), pair.slice(eqIdx + 1).trim());
    }

    // If hdnea present in query or incoming cookie, inject __hdnea__
    if (hdneaVal && !cookieMap.has('__hdnea__')) {
      cookieMap.set('__hdnea__', hdneaVal);
    }

    // If this is a Jio target or carries Jio auth, also populate query params and auth tokens into cookies
    if (isJioTarget || hasJioAuth) {
      for (const [pk, pv] of searchParams.entries()) {
        if (!cookieMap.has(pk)) cookieMap.set(pk, pv);
      }
      // Inject required Jio metadata headers if missing
      if (urlSrno && !fwdHeaders.get('srno')) fwdHeaders.set('srno', urlSrno);
      else if (!fwdHeaders.get('srno')) fwdHeaders.set('srno', '230203144000');

      if (urlChannelId && !fwdHeaders.get('channelid')) {
        fwdHeaders.set('channelid', urlChannelId);
        fwdHeaders.set('channelId', urlChannelId);
        fwdHeaders.set('channel_id', urlChannelId);
      }
      if (fwdHeaders.get('channelid') && !fwdHeaders.get('channel_id')) {
        fwdHeaders.set('channel_id', fwdHeaders.get('channelid'));
      }
      if (fwdHeaders.get('channel_id') && !fwdHeaders.get('channelid')) {
        fwdHeaders.set('channelid', fwdHeaders.get('channel_id'));
      }
      if (!fwdHeaders.get('appkey')) fwdHeaders.set('appkey', 'NzNiMDhlYzQyNjJm');
      if (!fwdHeaders.get('devicetype')) fwdHeaders.set('devicetype', 'phone');
      if (!fwdHeaders.get('os')) fwdHeaders.set('os', 'android');
      if (!fwdHeaders.get('osVersion')) fwdHeaders.set('osVersion', '13');
      if (!fwdHeaders.get('usergroup')) fwdHeaders.set('usergroup', 'tvYR7NSNn7rymo3F');
      if (!fwdHeaders.get('versionCode') && !fwdHeaders.get('versioncode')) fwdHeaders.set('versionCode', '424');
      if (!fwdHeaders.get('lbcookie')) fwdHeaders.set('lbcookie', '1');

      // Mirror critical session tokens to cookies for edge / CDN / load-balancer compatibility
      const sso = fwdHeaders.get('ssotoken');
      if (sso && !cookieMap.has('ssotoken')) cookieMap.set('ssotoken', sso);
      const auth = fwdHeaders.get('accesstoken');
      if (auth && !cookieMap.has('accesstoken')) cookieMap.set('accesstoken', auth);
      const lb = fwdHeaders.get('lbcookie');
      if (lb && !cookieMap.has('lbcookie')) cookieMap.set('lbcookie', lb);
      const uid = fwdHeaders.get('uniqueid') || fwdHeaders.get('uniqueId');
      if (uid && !cookieMap.has('uniqueId')) cookieMap.set('uniqueId', uid);
      const cid = fwdHeaders.get('channelid') || fwdHeaders.get('channel_id');
      if (cid && !cookieMap.has('channelid')) cookieMap.set('channelid', cid);
      const sr = fwdHeaders.get('srno');
      if (sr && !cookieMap.has('srno')) cookieMap.set('srno', sr);
    }

    if (cookieMap.size > 0) {
      const cookieStr = Array.from(cookieMap.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
      fwdHeaders.set('Cookie', cookieStr);
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
};
