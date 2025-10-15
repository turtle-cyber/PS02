# Docker Setup Guide

This project uses Docker and Docker Compose to orchestrate multiple services including the frontend, backend, and data pipeline components.

## Project Structure

```
PS02/
├── Frontend/              # React/Vite application
│   ├── Dockerfile        # Multi-stage build for production
│   ├── nginx.conf        # Nginx configuration
│   └── package.json      # Node.js dependencies
│
├── Backend/              # Node.js API server
│   ├── Dockerfile        # Backend container config
│   ├── server.js         # Express server
│   └── package.json      # Node.js dependencies
│
└── Pipeline/             # Data pipeline services
    ├── apps/             # Individual pipeline apps
    ├── frontend/         # Pipeline frontend API
    └── infra/
        └── docker-compose.yml  # Main orchestration file
```

## Services Overview

### Core Infrastructure
- **Kafka** - Message broker for pipeline events (port 9092)
- **Zookeeper** - Kafka coordination service
- **Redis** - Caching and deduplication (port 6379)
- **Chroma** - Vector database (port 8000)
- **Unbound** - DNS resolver

### User-Facing Services
- **Frontend** - React application (port 80)
- **Backend** - API server (port 3001)
- **Frontend-API** - Pipeline submission API (port 3000)

### Pipeline Services
- **ct-watcher** - Certificate transparency monitoring
- **dnstwist-runner** - Domain variation detection
- **normalizer** - Data normalization
- **dns-collector** - DNS and GeoIP collection
- **http-fetcher** - HTTP probing
- **url-router** - Request routing
- **feature-crawler** - Web page analysis (3 replicas)
- **rule-scorer** - Scoring and classification
- **chroma-ingestor** - Vector database ingestion
- **monitor-scheduler** - Periodic monitoring

## Quick Start

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+
- 8GB+ RAM recommended
- 20GB+ disk space

### Start All Services

```bash
cd Pipeline/infra
docker-compose up -d
```

### Start Specific Services

```bash
# Start only frontend and backend
docker-compose up -d frontend backend

# Start pipeline only
docker-compose up -d kafka redis chroma ct-watcher dns-collector
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f frontend
docker-compose logs -f backend

# Last 100 lines
docker-compose logs --tail=100 feature-crawler
```

### Check Service Status

```bash
docker-compose ps
```

### Stop Services

```bash
# Stop all
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

## Service Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost | React web application |
| Backend | http://localhost:3001 | Backend API server |
| Frontend-API | http://localhost:3000 | Pipeline submission API |
| Chroma | http://localhost:8000 | Vector database API |
| Kafka | localhost:9092 | Message broker |
| Redis | localhost:6379 | Cache server |

## Health Checks

Check service health:

```bash
# Frontend
curl http://localhost/health

# Backend
curl http://localhost:3001/health

# Frontend-API
curl http://localhost:3000/health

# Chroma
curl http://localhost:8000/api/v1/heartbeat
```

## Building Individual Services

### Frontend

```bash
cd Frontend
docker build -t ps02-frontend .
docker run -p 80:80 ps02-frontend
```

### Backend

```bash
cd Backend
docker build -t ps02-backend .
docker run -p 3001:3000 ps02-backend
```

## Development Workflow

### Development Mode (without Docker)

**Frontend:**
```bash
cd Frontend
npm install
npm run dev  # Starts on port 8080
```

**Backend:**
```bash
cd Backend
npm install
npm run dev  # Starts on port 3000
```

### Production Mode (with Docker)

```bash
cd Pipeline/infra
docker-compose up -d --build
```

## Environment Variables

### Frontend
- Built at compile time from Vite configuration
- API endpoints configured in nginx proxy

### Backend
- `PORT` - Server port (default: 3000)
- `KAFKA_BROKERS` - Kafka broker addresses
- `REDIS_HOST` - Redis hostname
- `CHROMA_HOST` - Chroma hostname
- `NODE_ENV` - Environment (production/development)
- `LOG_LEVEL` - Logging level (info/debug/error)

### Frontend-API
- `PORT` - Server port (default: 3000)
- `KAFKA_BROKERS` - Kafka broker addresses
- `KAFKA_TOPIC` - Default Kafka topic

## Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose logs service-name

# Rebuild without cache
docker-compose build --no-cache service-name
docker-compose up -d service-name
```

### Port Already in Use

```bash
# Check what's using the port
netstat -ano | findstr :80
netstat -ano | findstr :3000

# Kill the process or change the port in docker-compose.yml
```

### Kafka Connection Issues

```bash
# Restart Kafka and Zookeeper
docker-compose restart zookeeper kafka

# Wait for Kafka to be healthy
docker-compose logs -f kafka
```

### Out of Memory

```bash
# Check resource usage
docker stats

# Reduce replicas in docker-compose.yml
# Or increase Docker memory limit
```

### Clean Restart

```bash
# Stop everything
docker-compose down

# Remove all volumes and images
docker-compose down -v --rmi all

# Rebuild and start
docker-compose up -d --build
```

## Performance Tuning

### Adjust Service Replicas

Edit `docker-compose.yml`:

```yaml
feature-crawler:
  deploy:
    replicas: 3  # Increase or decrease based on load
```

### Memory Limits

```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          memory: 512M  # Adjust as needed
```

### Kafka Configuration

Adjust Kafka heap size in docker-compose.yml:

```yaml
kafka:
  environment:
    KAFKA_HEAP_OPTS: "-Xmx512M -Xms256M"  # Adjust heap size
```

## Monitoring

### View Resource Usage

```bash
docker stats
```

### Monitor Kafka Topics

```bash
docker exec -it kafka kafka-topics --list --bootstrap-server localhost:9092
docker exec -it kafka kafka-consumer-groups --list --bootstrap-server localhost:9092
```

### Check Redis Keys

```bash
docker exec -it redis redis-cli
> KEYS *
> DBSIZE
```

## Backup and Recovery

### Backup Volumes

```bash
# Backup Chroma data
docker run --rm -v pipeline_chroma:/data -v $(pwd):/backup alpine tar czf /backup/chroma-backup.tar.gz /data

# Backup Redis data
docker exec redis redis-cli SAVE
docker cp redis:/data/dump.rdb ./redis-backup.rdb
```

### Restore Volumes

```bash
# Restore Chroma
docker run --rm -v pipeline_chroma:/data -v $(pwd):/backup alpine tar xzf /backup/chroma-backup.tar.gz -C /

# Restore Redis
docker cp ./redis-backup.rdb redis:/data/dump.rdb
docker-compose restart redis
```

## Production Deployment

### Security Considerations

1. **Change default ports** - Don't expose Kafka, Redis on default ports
2. **Use secrets** - Store credentials in Docker secrets or external vault
3. **Enable authentication** - Configure Kafka SASL, Redis password
4. **Use HTTPS** - Add SSL termination proxy (nginx, traefik)
5. **Network isolation** - Use Docker networks to isolate services
6. **Resource limits** - Set memory/CPU limits for all services

### Recommended Production Changes

```yaml
# Add network isolation
networks:
  frontend-net:
  backend-net:
  pipeline-net:

# Use secrets
secrets:
  kafka-password:
    external: true
  redis-password:
    external: true
```

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [Kafka Documentation](https://kafka.apache.org/documentation/)
- [Redis Documentation](https://redis.io/documentation)
