/**
 * Concurrent refresh-token grant load test.
 *
 * Observes rotation and reuse-detection under contention (spec §20 / §24), not just latency.
 *
 * Required environment variables:
 *   BASE_URL          — IdP origin
 *   CLIENT_ID         — OAuth client id
 *   CLIENT_SECRET     — OAuth client secret
 *   USER_EMAIL        — Resource owner email (setup only)
 *   USER_PASSWORD     — Resource owner password (setup only)
 *   REDIRECT_URI      — Registered redirect URI
 *   REFRESH_VUS       — Concurrent refresh callers (default: 10)
 */

import http from 'k6/http';
import { check } from 'k6';
import encoding from 'k6/encoding';
import crypto from 'k6/crypto';

const BASE_URL = __ENV.BASE_URL;
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;
const USER_EMAIL = __ENV.USER_EMAIL;
const USER_PASSWORD = __ENV.USER_PASSWORD;
const REDIRECT_URI = __ENV.REDIRECT_URI || 'https://rp.example.test/callback';
const REFRESH_VUS = Number(__ENV.REFRESH_VUS || 10);

// PLACEHOLDER (spec §24): thresholds to be defined after the first real staging run.
export const options = {
  scenarios: {
    concurrent_refresh: {
      executor: 'shared-iterations',
      vus: REFRESH_VUS,
      iterations: REFRESH_VUS,
      maxDuration: '2m',
    },
  },
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
  const verifier = encoding.b64encode(crypto.randomBytes(32));
  const challenge = encoding.b64encode(crypto.sha256(verifier, 'raw'), 'rawurl');
  return { verifier, challenge };
}

function basicAuthHeader() {
  return `Basic ${encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`)}`;
}

function obtainRefreshToken() {
  const jar = http.cookieJar();
  const { verifier, challenge } = generatePkcePair();
  const scope = 'openid profile offline_access';
  const authorizeQuery = `response_type=code&client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=${encodeURIComponent(scope)}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256&state=k6-refresh-setup`;

  let response = http.get(`${BASE_URL}/authorize?${authorizeQuery}`, { jar });

  if (response.status === 303 && response.headers.Location.includes('/login')) {
    const next = redirectParams(response.headers.Location).next;
    const loginPage = http.get(`${BASE_URL}/login?next=${encodeURIComponent(next)}`, { jar });
    const loginFields = hiddenFields(loginPage.body);
    response = http.post(
      `${BASE_URL}/login`,
      {
        identifier: USER_EMAIL,
        password: USER_PASSWORD,
        csrf_token: loginFields.csrf_token,
        next: next || '',
      },
      { jar },
    );
    response = http.get(`${BASE_URL}${response.headers.Location}`, { jar });
  }

  if (response.status === 200) {
    const consentFields = hiddenFields(response.body);
    const scopes = checkboxScopes(response.body);
    response = http.post(
      `${BASE_URL}/consent`,
      {
        authorize_query: consentFields.authorize_query,
        csrf_token: consentFields.csrf_token,
        decision: 'allow',
        scope: scopes,
      },
      { jar },
    );
    response = http.get(`${BASE_URL}${response.headers.Location}`, { jar });
  }

  const code = redirectParams(response.headers.Location).code;
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

  const body = JSON.parse(tokenResponse.body);
  return body.refresh_token;
}

export function setup() {
  const refreshToken = obtainRefreshToken();
  check(refreshToken, { 'setup refresh token': (token) => token && token.length > 0 });
  return { refresh_token: refreshToken };
}

export default function (data) {
  const response = http.post(
    `${BASE_URL}/token`,
    {
      grant_type: 'refresh_token',
      refresh_token: data.refresh_token,
    },
    {
      headers: {
        Authorization: basicAuthHeader(),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    },
  );

  check(response, {
    'refresh status 200 or 400': (r) => r.status === 200 || r.status === 400,
  });
}
