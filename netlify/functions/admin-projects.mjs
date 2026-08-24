import { timingSafeEqual } from 'node:crypto';
import { getStore } from '@netlify/blobs';

const STORE_NAME = 'ferrn-project-portal';
const CONFIG_KEY = 'config/projects.csv';
const store = () => getStore({ name: STORE_NAME, consistency: 'strong' });

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

function safeEqualText(a = '', b = '') {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function adminAuthorized(request) {
  const configured = process.env.ADMIN_UPLOAD_KEY || '';
  const supplied = request.headers.get('x-admin-key') || '';
  return Boolean(configured) && safeEqualText(configured, supplied);
}

function normalizeHeader(value = '') {
  return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

function parseCSV(text = '') {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];
    if (ch === '"' && quoted && next === '"') { cell += '"'; i++; continue; }
    if (ch === '"') { quoted = !quoted; continue; }
    if (ch === ',' && !quoted) { row.push(cell.trim()); cell = ''; continue; }
    if ((ch === '\n' || ch === '\r') && !quoted) {
      if (ch === '\r' && next === '\n') i++;
      row.push(cell.trim());
      if (row.some(Boolean)) rows.push(row);
      row = [];
      cell = '';
      continue;
    }
    cell += ch;
  }

  row.push(cell.trim());
  if (row.some(Boolean)) rows.push(row);
  if (!rows.length) return [];

  const headers = rows[0].map(normalizeHeader);
  return rows.slice(1).map(values => {
    const record = {};
    headers.forEach((header, index) => { record[header] = values[index] ?? ''; });
    return record;
  }).filter(record => Object.values(record).some(Boolean));
}

function normalizeProject(record = {}) {
  const id = String(record.project || record.project_id || record.id || record.slug || '').trim().toUpperCase();
  return {
    id,
    password: String(record.password || '').trim(),
    name: String(record.display_name || record.name || id).trim() || id,
    brandAssets: String(record.brand_assets || record.brandAssets || '').trim(),
    projectFiles: String(record.project_files || record.projectFiles || '').trim(),
    figma: String(record.figma || '').trim(),
    backendRepo: String(record.backend_repo || record.backendRepo || '').trim(),
    frontendRepo: String(record.frontend_repo || record.frontendRepo || '').trim(),
  };
}

function cleanProjectId(value = '') {
  const project = String(value).trim().toUpperCase();
  return /^[A-Z0-9_-]{2,40}$/.test(project) ? project : '';
}

function csvEscape(value = '') {
  const text = String(value ?? '');
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function projectsToCSV(projects) {
  const header = 'project,password,display_name,brand_assets,project_files,figma,backend_repo,frontend_repo';
  const rows = projects.map(project => [
    project.id,
    project.password,
    project.name,
    project.brandAssets,
    project.projectFiles,
    project.figma,
    project.backendRepo,
    project.frontendRepo,
  ].map(csvEscape).join(','));
  return [header, ...rows].join('\n');
}

async function readProjects() {
  const blobCSV = await store().get(CONFIG_KEY, { type: 'text', consistency: 'strong' });
  const envCSV = process.env.PROJECTS_CSV || '';
  const sources = [blobCSV, envCSV].filter(Boolean);

  for (const csv of sources) {
    const projects = parseCSV(csv).map(normalizeProject).filter(project => project.id && project.password);
    if (projects.length) return projects;
  }
  return [];
}

async function saveProjects(projects) {
  const csv = projectsToCSV(projects);
  await store().set(CONFIG_KEY, csv, {
    metadata: { updatedAt: new Date().toISOString(), projects: projects.length },
  });
}

function publicAdminProject(project) {
  return {
    id: project.id,
    name: project.name,
    brandAssets: project.brandAssets,
    projectFiles: project.projectFiles,
    figma: project.figma,
    backendRepo: project.backendRepo,
    frontendRepo: project.frontendRepo,
    hasPassword: Boolean(project.password),
  };
}

export default async (request) => {
  if (!process.env.ADMIN_UPLOAD_KEY) {
    return json({ error: 'Admin tools are not configured yet.', code: 'ADMIN_NOT_CONFIGURED' }, 503);
  }
  if (!adminAuthorized(request)) {
    return json({ error: 'The admin key is incorrect.', code: 'INVALID_ADMIN_KEY' }, 401);
  }

  try {
    if (request.method === 'GET') {
      const projects = await readProjects();
      return json({ projects: projects.map(publicAdminProject) });
    }

    if (request.method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const incoming = normalizeProject(body);
      incoming.id = cleanProjectId(incoming.id);

      if (!incoming.id || !incoming.name) {
        return json({ error: 'Project code and project name are required.', code: 'MISSING_PROJECT_DETAILS' }, 400);
      }

      const projects = await readProjects();
      const index = projects.findIndex(project => project.id === incoming.id);

      if (index === -1 && !incoming.password) {
        return json({ error: 'A password is required for a new project.', code: 'PASSWORD_REQUIRED' }, 400);
      }

      if (index >= 0 && !incoming.password) incoming.password = projects[index].password;
      if (index >= 0) projects[index] = incoming;
      else projects.push(incoming);

      projects.sort((a, b) => a.name.localeCompare(b.name));
      await saveProjects(projects);
      return json({ ok: true, project: publicAdminProject(incoming), projects: projects.length });
    }

    if (request.method === 'DELETE') {
      const body = await request.json().catch(() => ({}));
      const id = cleanProjectId(body.id);
      if (!id) return json({ error: 'A valid project code is required.', code: 'INVALID_PROJECT_ID' }, 400);

      const projects = await readProjects();
      const next = projects.filter(project => project.id !== id);
      if (next.length === projects.length) return json({ error: 'Project not found.', code: 'PROJECT_NOT_FOUND' }, 404);

      await saveProjects(next);
      return json({ ok: true, projects: next.length });
    }

    return json({ error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' }, 405);
  } catch (error) {
    console.error('Ferrn admin projects error', error);
    return json({ error: 'Could not update projects right now. Please try again.', code: 'TEMPORARY_ERROR' }, 500);
  }
};
