# Ferrn Project Portal

Secure project workspace for Ferrn Digital Agency, deployed on Netlify.

## Security model

- The repository may remain public.
- Project passwords are **not** committed to GitHub.
- Secure uploaded HTML pages are stored in **Netlify Blobs**, not in this repository.
- The front end is a single file: `public/index.html` (HTML + CSS + JS).
- Server-side authentication lives in `netlify/functions/portal.mjs`.

## Required Netlify environment variables

Create these under **Project configuration → Environment variables** and make them available to Functions:

- `SESSION_SECRET` — a long random secret, ideally 32+ characters.
- `ADMIN_UPLOAD_KEY` — the key used to open admin upload/config actions.
- `PROJECTS_CSV` — initial project configuration. Once you upload a replacement CSV through the admin panel, the portal reads that copy from Netlify Blobs instead.

Example structure only — do **not** commit real passwords to GitHub:

```csv
project,password,display_name,brand_assets,project_files,figma,backend_repo,frontend_repo
PROJECT_CODE,CHANGE_ME,Project Name,https://drive.google.com/...,https://drive.google.com/...,https://www.figma.com/...,https://github.com/ORG/BACKEND.git,https://github.com/ORG/FRONTEND.git
```

Passwords may also be stored as `sha256:<hex digest>` in the CSV.

## Adding secure HTML files

1. Open the deployed portal.
2. Select **Admin upload** in the footer.
3. Enter `ADMIN_UPLOAD_KEY`.
4. Enter the project ID and upload a self-contained `.html` file.
5. The file appears automatically in that project's secure file list after login.

For best results, keep each HTML upload self-contained and below 4.5 MB.
