/**
 * Authorization Code + PKCE token exchange load test.
 *
 * Required environment variables:
 *   BASE_URL          — IdP origin (e.g. http://alb-dns-name)
 *   CLIENT_ID         — OAuth client id
 *   CLIENT_SECRET     — OAuth client secret
 *   USER_EMAIL        — Resource owner email
 *   USER_PASSWORD     — Resource owner password
 *   REDIRECT_URI      — Registered redirect URI (default: https://rp.example.test/callback)
 *   TOKEN_VUS         — Constant VUs (default: 15)
 *   TOKEN_DURATION     — Sustained duration (default: 45s)
 */

import http from 'k6/http';
import { check } from 'k6';
import encoding from 'k6/encoding';
import crypto from 'k6/crypto';

const TOKEN_VUS = Number(__ENV.TOKEN_VUS || 15);
const TOKEN_DURATION = __ENV.TOKEN_DURATION || '45s';

// PLACEHOLDER (spec §24): thresholds to be defined after the first real staging run.
export const options = {
  scenarios: {
    token_exchange: {
      executor: 'constant-vus',
      vus: TOKEN_VUS,
      duration: TOKEN_DURATION,
      gracefulStop: '10s',
    },
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  thresholds: {},
};

const BASE_URL = __ENV.BASE_URL;
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;
const USER_EMAIL = __ENV.USER_EMAIL;
const USER_PASSWORD = __ENV.USER_PASSWORD;
const REDIRECT_URI = __ENV.REDIRECT_URI || 'https://rp.example.test/callback';

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
  // Staging ALB is HTTP while session cookies are Secure; k6 would otherwise drop them.
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
  const response = http.get(url, { redirects: 0 });
  storeCookies(response);
  return response;
}

function post(url, body) {
  const response = http.post(url, body, { redirects: 0 });
  storeCookies(response);
  return response;
}

export default function () {
  const { verifier, challenge } = generatePkcePair();
  const scope = 'openid profile offline_access';
  const authorizeQuery = `response_type=code&client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=${encodeURIComponent(scope)}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256&state=k6-state`;

  let response = get(`${BASE_URL}/authorize?${authorizeQuery}`);

  if (response.status === 303 && String(header(response, 'Location') || '').includes('/login')) {
    const next = redirectParams(header(response, 'Location')).next;
    const loginPage = get(`${BASE_URL}/login?next=${encodeURIComponent(next || '')}`);
    check(loginPage, { 'login form': (r) => r.status === 200 });
    const loginFields = hiddenFields(loginPage.body);
    response = post(`${BASE_URL}/login`, {
      identifier: USER_EMAIL,
      password: USER_PASSWORD,
      csrf_token: loginFields.csrf_token,
      next: loginFields.next || next || '',
    });
    check(response, { 'login redirect': (r) => r.status === 303 });
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
    check(response, { 'consent redirect': (r) => r.status === 303 });
    response = get(resolve(header(response, 'Location')));
  }

  check(response, { 'authorization redirect': (r) => r.status === 303 });
  const code = redirectParams(header(response, 'Location') || '').code;
  check(code, { 'authorization code issued': (value) => value && value.length > 0 });

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
    },
  );

  check(tokenResponse, {
    'token exchange 200': (r) => r.status === 200,
    'access token present': (r) => {
      try {
        return JSON.parse(r.body).access_token !== undefined;
      } catch {
        return false;
      }
    },
  });
}
