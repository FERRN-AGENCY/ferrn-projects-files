import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { getStore } from '@netlify/blobs';

const STORE_NAME = 'ferrn-project-portal';
const SESSION_COOKIE = 'ferrn_session';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX_ATTEMPTS = 10;

const store = () => getStore({ name: STORE_NAME, consistency: 'strong' });

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders,
    },
  });
}

function normalizeHeader(value = '') {
  return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

function parseCSV(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (ch === '"' && quoted && next === '"') {
      cell += '"';
      i++;
      continue;
    }
    if (ch === '"') {
      quoted = !quoted;
      continue;
    }
    if (ch === ',' && !quoted) {
      row.push(cell.trim());
      cell = '';
      continue;
    }
    if ((ch === '\n' || ch === '\r') && !quoted) {
      if (ch === '\r' && next === '\n') i++;
      row.push(cell.trim());
      if (row.some((item) => item !== '')) rows.push(row);
      row = [];
      cell = '';
      continue;
    }
    cell += ch;
  }
  row.push(cell.trim());
  if (row.some((item) => item !== '')) rows.push(row);

  if (!rows.length) return [];
  const headers = rows[0].map(normalizeHeader);
  return rows.slice(1).map((values) => {
    const record = {};
    headers.forEach((header, index) => { record[header] = values[index] ?? ''; });
    return record;
  }).filter((record) => Object.values(record).some(Boolean));
}

function normalizeProject(record) {
  const id = String(record.project || record.project_id || record.slug || '').trim().toUpperCase();
  return {
    id,
    password: String(record.password || '').trim(),
    name: String(record.display_name || record.name || id).trim() || id,
    brandAssets: String(record.brand_assets || record.brand_assets_url || '').trim(),
    projectFiles: String(record.project_files || record.project_files_url || '').trim(),
    figma: String(record.figma || record.figma_url || '').trim(),
    backendRepo: String(record.backend_repo || record.backend || '').trim(),
    frontendRepo: String(record.frontend_repo || record.frontend || '').trim(),
  };
}

async function readProjects() {
  const blobCSV = await store().get('config/projects.csv', { type: 'text', consistency: 'strong' });
  const csv = blobCSV || process.env.PROJECTS_CSV || '';
  if (!csv.trim()) return [];
  return parseCSV(csv).map(normalizeProject).filter((project) => project.id && project.password);
}

function publicProject(project) {
  return {
    id: project.id,
    name: project.name,
    brandAssets: project.brandAssets,
    projectFiles: project.projectFiles,
    figma: project.figma,
    backendRepo: project.backendRepo,
    frontendRepo: project.frontendRepo,
  };
}

function safeEqualText(a = '', b = '') {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function passwordMatches(input, stored) {
  if (stored.startsWith('sha256:')) {
    return safeEqualText(sha256(input), stored.slice('sha256:'.length));
  }
  return safeEqualText(input, stored);
}

function sessionSecret() {
  return process.env.SESSION_SECRET || '';
}

function signSession(projectId) {
  const secret = sessionSecret();
  if (!secret) throw new Error('SESSION_SECRET is not configured');
  const payload = Buffer.from(JSON.stringify({
    p: projectId,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  })).toString('base64url');
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function readCookie(request, name) {
  const cookie = request.headers.get('cookie') || '';
  for (const part of cookie.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return rest.join('=');
  }
  return null;
}

function verifySession(request) {
  const secret = sessionSecret();
  const token = readCookie(request, SESSION_COOKIE);
  if (!secret || !token || !token.includes('.')) return null;
  const [payload, signature] = token.split('.');
  const expected = createHmac('sha256', secret).update(payload).digest('base64url');
  if (!safeEqualText(signature, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data?.p || !data?.exp || data.exp < Math.floor(Date.now() / 1000)) return null;
    return data;
  } catch {
    return null;
  }
}

function sessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

async function listProjectPages(projectId) {
  const prefix = `pages/${projectId.toLowerCase()}/`;
  const result = await store().list({ prefix });
  return (result.blobs || []).map(({ key, etag }) => ({ key, etag })).sort((a, b) => b.key.localeCompare(a.key));
}

async function projectPayload(project) {
  return {
    project: publicProject(project),
    pages: await listProjectPages(project.id),
  };
}

function adminAuthorized(request) {
  const configured = process.env.ADMIN_UPLOAD_KEY || '';
  const supplied = request.headers.get('x-admin-key') || '';
  return Boolean(configured) && safeEqualText(configured, supplied);
}

function cleanProjectId(value = '') {
  const project = String(value).trim().toUpperCase();
  return /^[A-Z0-9_-]{2,40}$/.test(project) ? project : '';
}

function cleanFilename(filename = '') {
  const base = String(filename).split(/[\\/]/).pop() || 'project-page.html';
  const cleaned = base
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '')
    .slice(0, 100);
  return cleaned || 'project-page.html';
}

async function rateLimitKey(context, projectId) {
  const ip = context?.ip || context?.geo?.city?.name || 'unknown';
  return `rate/${sha256(`${ip}|${projectId}`).slice(0, 40)}`;
}

async function checkRateLimit(context, projectId) {
  const key = await rateLimitKey(context, projectId);
  const data = await store().get(key, { type: 'json', consistency: 'strong' });
  const now = Date.now();
  if (!data || (now - Number(data.startedAt || 0)) > RATE_WINDOW_MS) return { allowed: true, key, count: 0, startedAt: now };
  return { allowed: Number(data.count || 0) < RATE_MAX_ATTEMPTS, key, count: Number(data.count || 0), startedAt: Number(data.startedAt || now) };
}

async function registerFailedLogin(rate) {
  await store().setJSON(rate.key, {
    count: rate.count + 1,
    startedAt: rate.startedAt,
  });
}

async function clearRateLimit(rate) {
  try { await store().delete(rate.key); } catch {}
}

async function requireSessionProject(request) {
  const session = verifySession(request);
  if (!session) return null;
  const projects = await readProjects();
  return projects.find((project) => project.id === session.p) || null;
}

export default async (request, context) => {
  const url = new URL(request.url);
  const action = url.searchParams.get('action') || '';

  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });

  try {
    if (action === 'login' && request.method === 'POST') {
      if (!sessionSecret()) return json({ error: 'Portal setup is incomplete: SESSION_SECRET is missing in Netlify.' }, 503);
      const body = await request.json().catch(() => ({}));
      const projectId = cleanProjectId(body.project);
      const password = String(body.password || '');
      if (!projectId || !password) return json({ error: 'Enter a valid project and password.' }, 400);

      const rate = await checkRateLimit(context, projectId);
      if (!rate.allowed) return json({ error: 'Too many attempts. Try again in a few minutes.' }, 429);

      const projects = await readProjects();
      const project = projects.find((item) => item.id === projectId);
      if (!project || !passwordMatches(password, project.password)) {
        await registerFailedLogin(rate);
        return json({ error: 'Access denied. Check the project name and password.' }, 401);
      }

      await clearRateLimit(rate);
      const token = signSession(project.id);
      return json(await projectPayload(project), 200, { 'Set-Cookie': sessionCookie(token) });
    }

    if (action === 'me' && request.method === 'GET') {
      const project = await requireSessionProject(request);
      if (!project) return json({ error: 'Not signed in.' }, 401);
      return json(await projectPayload(project));
    }

    if (action === 'logout' && request.method === 'POST') {
      return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
    }

    if (action === 'page' && request.method === 'GET') {
      const project = await requireSessionProject(request);
      if (!project) return new Response('Not signed in.', { status: 401, headers: { 'Cache-Control': 'no-store' } });
      const key = url.searchParams.get('key') || '';
      const prefix = `pages/${project.id.toLowerCase()}/`;
      if (!key.startsWith(prefix)) return new Response('Not allowed.', { status: 403, headers: { 'Cache-Control': 'no-store' } });
      const html = await store().get(key, { type: 'text', consistency: 'strong' });
      if (html === null) return new Response('File not found.', { status: 404, headers: { 'Cache-Control': 'no-store' } });
      return new Response(html, {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'private, no-store, max-age=0',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer',
        },
      });
    }

    if (action === 'admin-upload' && request.method === 'POST') {
      if (!adminAuthorized(request)) return json({ error: 'Invalid admin key.' }, 401);
      const form = await request.formData();
      const projectId = cleanProjectId(form.get('project'));
      const file = form.get('file');
      if (!projectId || !(file instanceof File)) return json({ error: 'Project and HTML file are required.' }, 400);

      const projects = await readProjects();
      if (!projects.some((project) => project.id === projectId)) return json({ error: 'That project is not configured in the portal CSV.' }, 404);

      const filename = cleanFilename(file.name);
      if (!/\.html?$/i.test(filename)) return json({ error: 'Only .html or .htm files are allowed.' }, 400);
      if (file.size > 4.5 * 1024 * 1024) return json({ error: 'HTML file must be smaller than 4.5 MB.' }, 413);

      const html = await file.text();
      const key = `pages/${projectId.toLowerCase()}/${Date.now()}--${filename}`;
      await store().set(key, html, {
        metadata: {
          project: projectId,
          filename,
          uploadedAt: new Date().toISOString(),
        },
      });
      return json({ ok: true, key });
    }

    if (action === 'admin-csv' && request.method === 'POST') {
      if (!adminAuthorized(request)) return json({ error: 'Invalid admin key.' }, 401);
      const csv = await request.text();
      if (!csv.trim()) return json({ error: 'CSV cannot be empty.' }, 400);
      if (Buffer.byteLength(csv, 'utf8') > 256 * 1024) return json({ error: 'CSV is too large.' }, 413);

      const projects = parseCSV(csv).map(normalizeProject).filter((project) => project.id && project.password);
      if (!projects.length) return json({ error: 'CSV must include at least one row with project and password values.' }, 400);
      const invalid = projects.find((project) => !cleanProjectId(project.id));
      if (invalid) return json({ error: `Invalid project ID: ${invalid.id}` }, 400);

      await store().set('config/projects.csv', csv, {
        metadata: { updatedAt: new Date().toISOString(), projects: projects.length },
      });
      return json({ ok: true, projects: projects.length });
    }

    return json({ error: 'Not found.' }, 404);
  } catch (error) {
    console.error('Ferrn portal error', error);
    return json({ error: 'Something went wrong on the server.' }, 500);
  }
};
