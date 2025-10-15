# Docker Configuration Changes Summary

## Overview
Updated Docker configuration to reflect the new folder structure with separate Backend, Frontend, and Pipeline directories. Removed nginx in favor of Vite's preview server and updated all service configurations.

---

## Changes Made

### 1. **Frontend Dockerfile** ([Frontend/Dockerfile](Frontend/Dockerfile))
**Changed from:** Multi-stage build with nginx
**Changed to:** Single-stage build with Vite preview server

- Uses Node.js 22 Alpine
- Builds with `npm run build`
- Serves with `npm run preview` on port **4173**
- Removed nginx dependency
- More lightweight and simpler configuration

### 2. **Frontend Port Change**
- **Old Port:** 80 (nginx)
- **New Port:** 4173 (Vite preview)
- Updated in [docker-compose.yml](Pipeline/infra/docker-compose.yml)

### 3. **Removed Services**
- **Removed:** `frontend-api` service from docker-compose.yml
  - This was accidentally placed in Pipeline/frontend directory
  - The actual frontend-api still exists in Pipeline/frontend/frontend-api

### 4. **Backend Package.json** ([Backend/package.json](Backend/package.json))
**Updated:**
- Name: `phishing-backend-api` (from `phishing-frontend-api`)
- Description: Updated to reflect stats and monitoring functionality
- Dependencies remain the same:
  - `chromadb` - For Chroma DB integration
  - `redis` - For Redis stats
  - `kafkajs` - For Kafka integration
  - `express`, `cors`, `helmet`, `winston` - Server framework and utilities

### 5. **Docker Compose Updates** ([Pipeline/infra/docker-compose.yml](Pipeline/infra/docker-compose.yml))

#### Frontend Service:
```yaml
frontend:
  build:
    context: ../../Frontend
  ports:
    - "4173:4173"  # Changed from 80:80
  healthcheck:
    # Updated to check port 4173 with Node.js
```

#### Backend Service:
```yaml
backend:
  build:
    context: ../../Backend
  ports:
    - "3001:3000"
  environment:
    - REDIS_HOST=redis
    - CHROMA_HOST=chroma
    - KAFKA_BROKERS=kafka:9092
  depends_on:
    - kafka
    - redis
    - chroma
```

### 6. **Documentation Updates** ([DOCKER.md](DOCKER.md))

#### Updated Sections:
- **Project Structure** - Removed nginx.conf reference, updated descriptions
- **Service Endpoints** - Updated Frontend port to 4173
- **Added:** Backend API Endpoints table with all routes:
  - `/health` - Health check
  - `/api/url-detection` - Chroma DB URLs
  - `/api/monitoring/stats` - Monitoring statistics
  - `/api/dnstwist/stats` - DNSTwist statistics
  - `/api/fcrawler/stats` - Feature crawler statistics
- **Health Checks** - Updated curl commands for new ports
- **Environment Variables** - Added detailed Backend env vars
- **Building Instructions** - Updated port mappings

---

## Service Architecture

### Current Setup:

```
┌─────────────────────────────────────────────────────────┐
│                     User Access                         │
└─────────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
        ┌───────▼──────┐       ┌───────▼──────┐
        │   Frontend   │       │   Backend    │
        │  (Vite:4173) │       │   (API:3001) │
        └──────────────┘       └───────┬──────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
            ┌───────▼────┐     ┌──────▼─────┐    ┌──────▼─────┐
            │   Redis    │     │   Chroma   │    │   Kafka    │
            │  (:6379)   │     │  (:8000)   │    │  (:9092)   │
            └────────────┘     └────────────┘    └────────────┘
```

---

## API Routes Summary

### Backend Routes ([Backend/server.js](Backend/server.js))

| Route | File | Purpose |
|-------|------|---------|
| `/health` | server.js | Health check endpoint |
| `/api/url-detection` | routes/urlDetection/url-detection.js | Fetch URLs from Chroma DB |
| `/api/monitoring/*` | routes/monitoring/monitoring-stats.js | Monitoring queue stats |
| `/api/dnstwist/*` | routes/dnstwist/dnstwist-stats.js | DNSTwist processing stats |
| `/api/fcrawler/*` | routes/featureCrawler/fcrawler-stats.js | Feature crawler progress |

### Backend Dependencies:
- **chromadb**: ^3.0.17 - Vector database client
- **redis**: ^4.6.13 - Redis client for stats
- **kafkajs**: ^2.2.4 - Kafka producer/consumer
- **express**: ^4.18.2 - Web framework
- **winston**: ^3.11.0 - Logging

---

## Quick Start Commands

### Start Everything:
```bash
cd Pipeline/infra
docker-compose up -d
```

### Start Just Frontend & Backend:
```bash
cd Pipeline/infra
docker-compose up -d frontend backend redis chroma kafka
```

### Access Services:
- **Frontend:** http://localhost:4173
- **Backend API:** http://localhost:3001/api/monitoring/stats
- **Backend Health:** http://localhost:3001/health

### View Logs:
```bash
docker-compose logs -f frontend
docker-compose logs -f backend
```

---

## Files Modified

1. ✅ [Frontend/Dockerfile](Frontend/Dockerfile) - Changed to Vite preview
2. ✅ [Frontend/.dockerignore](Frontend/.dockerignore) - Added Docker ignore rules
3. ✅ [Backend/package.json](Backend/package.json) - Updated name and description
4. ✅ [Backend/.dockerignore](Backend/.dockerignore) - Added Docker ignore rules
5. ✅ [Pipeline/infra/docker-compose.yml](Pipeline/infra/docker-compose.yml) - Removed frontend-api, updated frontend port
6. ✅ [DOCKER.md](DOCKER.md) - Updated documentation

## Files Created

1. ✅ [CHANGES.md](CHANGES.md) - This file

---

## Testing Checklist

Before deploying, test the following:

### Frontend:
- [ ] Build succeeds: `cd Frontend && npm run build`
- [ ] Preview works: `npm run preview`
- [ ] Docker build: `docker build -t test-frontend .`
- [ ] Container runs: `docker run -p 4173:4173 test-frontend`
- [ ] Access at: http://localhost:4173

### Backend:
- [ ] Dependencies install: `cd Backend && npm install`
- [ ] Server starts: `npm start`
- [ ] Docker build: `docker build -t test-backend .`
- [ ] Container runs: `docker run -p 3001:3000 test-backend`
- [ ] Health check: `curl http://localhost:3001/health`

### Docker Compose:
- [ ] All services start: `cd Pipeline/infra && docker-compose up`
- [ ] Frontend accessible: http://localhost:4173
- [ ] Backend accessible: http://localhost:3001/health
- [ ] Backend stats work: http://localhost:3001/api/monitoring/stats
- [ ] No port conflicts
- [ ] All health checks pass: `docker-compose ps`

---

## Notes

### Why Vite Preview Instead of Nginx?
1. **Simpler:** One-stage Docker build instead of multi-stage
2. **Smaller:** No need for nginx image
3. **Faster:** Direct Node.js serving without nginx layer
4. **Consistent:** Same server for dev and production preview
5. **Easier to debug:** Node.js process, familiar tooling

### Why Remove Frontend-API Service?
- It was accidentally placed in Pipeline/frontend directory
- The actual frontend-api should remain in Pipeline/frontend/frontend-api
- If you need a submission API, that should be added separately

### Production Considerations
For production with high traffic, consider:
1. Adding nginx as reverse proxy in front of Vite preview
2. Using CDN for static assets
3. Enabling gzip compression
4. Adding SSL termination
5. Load balancing across multiple frontend instances

---

## Rollback Instructions

If you need to revert to nginx:

1. Restore [Frontend/Dockerfile](Frontend/Dockerfile) with multi-stage nginx build
2. Restore [Frontend/nginx.conf](Frontend/nginx.conf)
3. Update docker-compose.yml frontend port back to `80:80`
4. Update DOCKER.md references from 4173 to 80

Git command (if committed):
```bash
git revert <commit-hash>
```

---

## Support

For issues or questions:
1. Check [DOCKER.md](DOCKER.md) for troubleshooting
2. View logs: `docker-compose logs <service-name>`
3. Check service health: `docker-compose ps`
4. Verify ports: `netstat -ano | findstr :<port>`
