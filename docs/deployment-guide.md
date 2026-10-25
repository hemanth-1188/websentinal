# WebShield Production Deployment Guide

This guide details step-by-step instructions for deploying **WebShield** permanently to production.

---

## Architecture Overview

WebShield consists of:
1. **Frontend:** React 18 + Vite SPA (served via Nginx or static host)
2. **Backend:** Node.js Express API + Scanner Engine & BullMQ Worker
3. **Database:** MongoDB 7.0 (Stores scans, findings, users, reports, and audit trails)
4. **Cache & Queue:** Redis 7 (BullMQ async scanning queues, live progress cache, and rate limiting)

---

## Deployment Option 1: VPS with Docker Compose (Recommended)

Running all services via Docker Compose on a Virtual Private Server (VPS) such as **DigitalOcean Droplet ($6/mo)**, **Hetzner Cloud (€4/mo)**, **AWS EC2 (t3.small)**, or **Linode** is the easiest, most cost-effective method with no timeouts.

### Prerequisites
- A Linux VPS (Ubuntu 22.04 or 24.04 LTS recommended, 2GB+ RAM)
- A domain name (e.g. `webshield.yourdomain.com`) pointing to your VPS IP

### Step 1: Install Docker & Docker Compose on the VPS
SSH into your server and run:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl ufw

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose Plugin
sudo apt-get install -y docker-compose-plugin
```

### Step 2: Clone the Repository
```bash
cd /opt
sudo git clone https://github.com/hemanth-1188/websentinal.git webshield
cd webshield
```

### Step 3: Configure Production Environment Variables
Create your production `.env` file:
```bash
cp .env.example .env
nano .env
```

Ensure the following variables are customized:
```env
PORT=5000
NODE_ENV=production
JWT_SECRET=generate_a_secure_random_64_char_secret_key_here

# MongoDB credentials
MONGO_USER=webshield_admin
MONGO_PASSWORD=choose_a_strong_database_password
MONGO_DB=webshield_db
MONGODB_URI=mongodb://webshield_admin:choose_a_strong_database_password@mongodb:27017/webshield_db?authSource=admin

# Redis
REDIS_URL=redis://redis:6379

# Production Frontend Origin
CORS_ORIGIN=https://webshield.yourdomain.com

# Scanner Engine Tuning
MAX_SCAN_DURATION=300
MAX_REQUESTS_PER_SCAN=100
MAX_CONCURRENT_REQUESTS=5
REQUEST_TIMEOUT=10000
MAX_REDIRECTS=5
ALLOW_LOCAL_DEMO_TARGET=false
```

### Step 4: Build and Start Containers
```bash
docker compose up -d --build
```

Verify that all containers are healthy:
```bash
docker compose ps
```

### Step 5: Setup Automatic HTTPS / SSL with Caddy (2 Minutes)
Caddy automatically provisions and renews free Let's Encrypt SSL certificates.

1. Install Caddy:
   ```bash
   sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
   sudo apt update
   sudo apt install caddy
   ```

2. Configure `/etc/caddy/Caddyfile`:
   ```caddy
   webshield.yourdomain.com {
       # Route API requests to backend
       handle /api/* {
           reverse_proxy localhost:5000
       }
       # Route all other requests to frontend
       handle {
           reverse_proxy localhost:3000
       }
   }
   ```

3. Restart Caddy:
   ```bash
   sudo systemctl restart caddy
   ```

Your platform is now live with automatic HTTPS at `https://webshield.yourdomain.com`!

---

## Deployment Option 2: Managed Cloud Services (Render + MongoDB Atlas)

If you prefer managed serverless platforms without maintaining a Linux VPS:

### 1. Database: MongoDB Atlas (Free M0 Cluster Forever)
1. Sign up at [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas).
2. Create a free **M0 Sandbox** cluster.
3. Under **Database Access**, create a user (e.g. `webshield_user` with a strong password).
4. Under **Network Access**, add `0.0.0.0/0` (allow access from anywhere) or specify your host IPs.
5. Click **Connect** -> **Drivers** and copy your connection string:
   ```
   mongodb+srv://webshield_user:<password>@cluster0.abcde.mongodb.net/webshield_db?retryWrites=true&w=majority
   ```

### 2. Cache / Queue: Upstash Redis (Free Forever)
1. Sign up at [upstash.com](https://upstash.com).
2. Create a free Redis database.
3. Copy the `rediss://...` connection string.

### 3. Backend: Render.com Web Service
1. Connect your GitHub repository `hemanth-1188/websentinal` to [Render.com](https://render.com).
2. Click **New +** -> **Blueprint**, and point to the [`render.yaml`](../render.yaml) file in the repo, or create a Web Service manually:
   - **Root Directory:** `backend`
   - **Build Command:** `npm install && npm run build`
   - **Start Command:** `npm start`
   - **Environment Variables:**
     - `NODE_ENV`: `production`
     - `PORT`: `5000`
     - `JWT_SECRET`: *(Generate a secure 64-character secret)*
     - `MONGODB_URI`: *(Your MongoDB Atlas connection URI)*
     - `REDIS_URL`: *(Your Upstash Redis connection URI)*
     - `CORS_ORIGIN`: `https://your-frontend-app.vercel.app`

### 4. Frontend: Vercel / Netlify / Render
1. Deploy the `frontend/` directory to **Vercel** or **Render Static Site**:
   - **Root Directory:** `frontend`
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
2. Add rewrite rule for Single Page App routing (already configured in [`render.yaml`](../render.yaml) and [`vercel.json`](../frontend/vercel.json) if using Vercel).
3. Set environment variable `VITE_API_URL` pointing to your deployed backend URL.

---

## Production Security Best Practices

1. **Firewall (UFW):** If deploying on a VPS, close unnecessary ports:
   ```bash
   sudo ufw allow ssh
   sudo ufw allow http
   sudo ufw allow https
   sudo ufw enable
   ```
   *(Ensure ports 27017 and 6379 are NOT exposed publicly; only Docker internal network should communicate with them.)*
2. **Rotate Default Credentials:** Immediately change the default admin credentials after initial startup:
   - Log in with `admin@webshield.io` / `Admin@123456`
   - Update credentials or delete default users via the Admin dashboard.
3. **Database Backups:**
   - On VPS: Set up a daily cron job with `mongodump` to backup collections to S3 or remote storage.
   - On Atlas: Automatic continuous snapshots are included.
4. **Log Monitoring:** Inspect backend logs using:
   ```bash
   docker compose logs -f backend
   ```
