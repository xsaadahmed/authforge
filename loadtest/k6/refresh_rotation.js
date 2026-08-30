/**
 * Concurrent refresh-token grant load test.
 *
 * Observes rotation and reuse-detection under contention (spec §20 / §24), not just latency.
 *
 * Required environment variables:
 *   BASE_URL          — IdP origin
 *   CLIENT_ID         — OAuth client id
 *   CLIENT_SECRET     — OAuth client secret
 *   USER_EMAIL        — Resource owner email
 *   USER_PASSWORD     — Resource owner password
 *   REDIRECT_URI         — Registered redirect URI
 *   REFRESH_VUS          — Constant VUs repeating independent races (default: 10)
 *   REFRESH_DURATION     — Sustained duration (default: 45s)
 *   REFRESH_CONTENTION   — Simultaneous POSTs of one raw refresh token per iteration (default: 5)
 *
 * Failure-rate mechanism (why the 5-VU / 5-iteration run showed ~40% http_req_failed):
 *   setup() issued ONE refresh token. Every VU then POSTed /token with that SAME raw
 *   value. claim_for_rotation is an atomic UPDATE … WHERE used_at IS NULL: exactly one
 *   request stamps used_at and gets 200; the rest see used_at already set, trip
 *   REUSE_DETECTED, revoke the family, and return 400 invalid_grant. k6 counts those
 *   400s as http_req_failed. The previous 10-request total was ~5 successful OAuth
 *   setup calls plus 5 refresh POSTs (1×200 + 4×400) → 4/10 = 40%. That is reuse
 *   detection under contention, not transport errors — but a single 5-way race is too
 *   small to be a stable rate.
 *
 * This script keeps that race (REFRESH_CONTENTION simultaneous POSTs of one token)
 * and repeats it for REFRESH_DURATION so the percentage is measured over many families.
 */

import http from 'k6/http';
import { check } from 'k6';
import encoding from 'k6/encoding';
import crypto from 'k6/crypto';
import { Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL;
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;
const USER_EMAIL = __ENV.USER_EMAIL;
const USER_PASSWORD = __ENV.USER_PASSWORD;
const REDIRECT_URI = __ENV.REDIRECT_URI || 'https://rp.example.test/callback';
const REFRESH_VUS = Number(__ENV.REFRESH_VUS || 10);
const REFRESH_DURATION = __ENV.REFRESH_DURATION || '45s';
const REFRESH_CONTENTION = Number(__ENV.REFRESH_CONTENTION || 5);

const refreshTokenDuration = new Trend('refresh_token_duration', true);

// PLACEHOLDER (spec §24): thresholds to be defined after the first real staging run.
export const options = {
  scenarios: {
    concurrent_refresh: {
      executor: 'constant-vus',
      vus: REFRESH_VUS,
      duration: REFRESH_DURATION,
      gracefulStop: '10s',
    },
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  thresholds: {},
};

function hiddenFields(markup) {
  const fields = {};
  const pattern = /<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"/gi;
  let match;
  while ((match = pattern.exec(markup)) !== null) {
    fields[match[1]] = match[2].replace(/&amp;/g, '&');
  }
  return fields;
}

function checkboxScopes(markup) {
  const scopes = [];
  const pattern = /<input[^>]*type="checkbox"[^>]*name="scope"[^>]*value="([^"]+)"/gi;
  let match;
  while ((match = pattern.exec(markup)) !== null) {
    scopes.push(match[1]);
  }
  return scopes;
}

function redirectParams(location) {
  const query = location.split('?')[1] || '';
  const params = {};
  for (const part of query.split('&')) {
    const [key, value] = part.split('=');
    if (key) params[key] = decodeURIComponent(value || '');
  }
  return params;
}

function generatePkcePair() {
  const verifier = encoding.b64encode(crypto.randomBytes(32), 'rawurl');
  const challenge = crypto.sha256(verifier, 'base64rawurl');
  return { verifier, challenge };
}

function basicAuthHeader() {
  return `Basic ${encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`)}`;
}

function header(response, name) {
  return response.headers[name] || response.headers[name.toLowerCase()];
}

function storeCookies(response) {
  const raw = header(response, 'Set-Cookie');
  if (!raw) return;
  const lines = Array.isArray(raw) ? raw : [raw];
  const jar = http.cookieJar();
  for (const line of lines) {
    const nv = String(line).split(';')[0];
    const eq = nv.indexOf('=');
    if (eq > 0) jar.set(BASE_URL, nv.slice(0, eq).trim(), nv.slice(eq + 1));
  }
}

function resolve(location) {
  if (!location) return BASE_URL;
  if (location.startsWith('http://') || location.startsWith('https://')) return location;
  return `${BASE_URL}${location.startsWith('/') ? '' : '/'}${location}`;
}

function get(url) {
  const response = http.get(url, { redirects: 0, tags: { name: 'oauth_setup' } });
  storeCookies(response);
  return response;
}

function post(url, body) {
  const response = http.post(url, body, { redirects: 0, tags: { name: 'oauth_setup' } });
  storeCookies(response);
  return response;
}

function obtainRefreshToken() {
  const { verifier, challenge } = generatePkcePair();
  const scope = 'openid profile offline_access';
  const authorizeQuery = `response_type=code&client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=${encodeURIComponent(scope)}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256&state=k6-refresh-setup`;

  let response = get(`${BASE_URL}/authorize?${authorizeQuery}`);

  if (response.status === 303 && String(header(response, 'Location') || '').includes('/login')) {
    const next = redirectParams(header(response, 'Location')).next;
    const loginPage = get(`${BASE_URL}/login?next=${encodeURIComponent(next || '')}`);
    const loginFields = hiddenFields(loginPage.body);
    response = post(`${BASE_URL}/login`, {
      identifier: USER_EMAIL,
      password: USER_PASSWORD,
      csrf_token: loginFields.csrf_token,
      next: loginFields.next || next || '',
    });
    response = get(resolve(header(response, 'Location')));
  }

  if (response.status === 200 && String(response.body || '').includes('name="csrf_token"')) {
    const consentFields = hiddenFields(response.body);
    const scopes = checkboxScopes(response.body);
    response = post(`${BASE_URL}/consent`, {
      authorize_query: consentFields.authorize_query,
      csrf_token: consentFields.csrf_token,
      decision: 'allow',
      scope: scopes,
    });
    response = get(resolve(header(response, 'Location')));
  }

  const code = redirectParams(header(response, 'Location') || '').code;
  const tokenResponse = http.post(
    `${BASE_URL}/token`,
    {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    },
    {
      headers: {
        Authorization: basicAuthHeader(),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      tags: { name: 'oauth_setup' },
    },
  );

  const body = JSON.parse(tokenResponse.body);
  return body.refresh_token;
}

export default function () {
  const refreshToken = obtainRefreshToken();
  check(refreshToken, { 'issued refresh token': (token) => token && token.length > 0 });
  if (!refreshToken) {
    return;
  }

  const payload = {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  };
  const params = {
    headers: {
      Authorization: basicAuthHeader(),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    tags: { name: 'refresh_token' },
  };
  const requests = Array.from({ length: REFRESH_CONTENTION }, () => [
    'POST',
    `${BASE_URL}/token`,
    payload,
    params,
  ]);

  const responses = http.batch(requests);
  for (const response of responses) {
    refreshTokenDuration.add(response.timings.duration);
    check(response, {
      'refresh status 200 or 400': (r) => r.status === 200 || r.status === 400,
    });
  }
}
