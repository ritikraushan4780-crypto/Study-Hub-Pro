# StudyHub Pro — Node.js + Express Backend

Your Firebase credentials now live **only on the server**. The browser never sees your API key.

---

## What changed (and why)

| Before | After |
|--------|-------|
| Firebase config in `index.html` (visible to anyone) | Config in `.env` on your server only |
| Passwords stored in plaintext in Firestore | Passwords hashed with bcrypt |
| No rate limiting | Login/register rate limited |
| Anyone could write to Firestore directly | All writes go through authenticated API |

---

## Setup (one time)

### 1. Get your Firebase Service Account key

1. Go to [Firebase Console](https://console.firebase.google.com) → your project
2. Click ⚙️ Project Settings → **Service Accounts**
3. Click **Generate new private key** → download the JSON file

### 2. Clone / copy this project

```
studyhub/
├── server.js
├── package.json
├── .env.example
├── .gitignore
└── public/
    └── index.html
```

### 3. Install dependencies

```bash
cd studyhub
npm install
```

### 4. Create your `.env` file

```bash
cp .env.example .env
```

Open `.env` and fill in values from the service account JSON you downloaded:

```env
FIREBASE_PROJECT_ID=study-hub-pro-372f6
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-xxxxx@study-hub-pro-372f6.iam.gserviceaccount.com
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIEvA...\n-----END PRIVATE KEY-----\n"

PORT=3000
SESSION_SECRET=pick_a_long_random_string_here_minimum_32_chars
ALLOWED_ORIGINS=http://localhost:3000
```

> ⚠️ The private key must be wrapped in double quotes. Keep all `\n` as-is — do NOT replace them with real newlines.

### 5. Lock down Firestore Security Rules

In Firebase Console → Firestore → Rules, paste this:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Block ALL direct client access — only your server (Admin SDK) can access
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

This is the most important step. Your server uses the Admin SDK which bypasses these rules, so your app still works — but no one can directly hit your Firestore anymore.

### 6. Run the server

```bash
# Development (auto-restarts on changes)
npm run dev

# Production
npm start
```

Visit: **http://localhost:3000**

Default login: `admin` / `admin123` (change this immediately after first login)

---

## Deploying to production

### Option A: VPS / cloud VM (DigitalOcean, AWS EC2, etc.)

```bash
# Install Node.js 18+, then:
npm install
cp .env.example .env
# Fill in .env values
npm start

# Use PM2 to keep it running:
npm install -g pm2
pm2 start server.js --name studyhub
pm2 save
```

Set `ALLOWED_ORIGINS=https://yourdomain.com` in `.env`.

Use **Nginx** as a reverse proxy in front of Node:

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Option B: Railway / Render (easiest)

1. Push this folder to a GitHub repo (`.env` is in `.gitignore` so it won't be committed)
2. Create a new project on [Railway](https://railway.app) or [Render](https://render.com)
3. Add environment variables in their dashboard (same as your `.env` content)
4. Deploy — done

---

## Security checklist

- [x] Firebase config hidden from browser
- [x] Passwords hashed with bcrypt (auto-migrates old plaintext on login)
- [x] Rate limiting on auth endpoints (20 req / 15 min)
- [x] Session tokens signed with HMAC-SHA256
- [x] Students cannot modify other users' data
- [x] Students cannot elevate their own role
- [ ] **Set Firestore rules to deny all** (Step 5 above — do this!)
- [ ] Change default admin password after first login
- [ ] Set a strong `SESSION_SECRET` in `.env`
- [ ] Use HTTPS in production (Nginx + Certbot / Let's Encrypt)
