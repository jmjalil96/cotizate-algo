# Graceful Shutdown

## Overview
The application implements graceful shutdown to ensure clean termination and prevent data loss.

## Features
- Handles SIGTERM (Docker/Kubernetes) and SIGINT (Ctrl+C) signals
- Stops accepting new connections immediately
- Waits for active requests to complete (30s timeout)
- Closes database connections properly
- Performs custom cleanup if needed
- Logs all shutdown steps

## How it Works

### Shutdown Sequence
1. Signal received (SIGTERM/SIGINT)
2. Stop accepting new connections
3. Wait for active requests to finish
4. Close database connections
5. Run custom cleanup functions
6. Exit with code 0 (success)

### Timeout Protection
If graceful shutdown doesn't complete within 30 seconds, the process force exits with code 1.

## Testing

### Local Testing (Ctrl+C)
```bash
npm run dev
# Press Ctrl+C
# Watch logs for graceful shutdown
```

### Docker Testing
```bash
# Start container
docker run -d --name test-app cotizate-app:latest

# Send SIGTERM
docker stop test-app

# Check logs
docker logs test-app
```

### Kubernetes Testing
```bash
# Delete pod (sends SIGTERM)
kubectl delete pod <pod-name>

# Check pod logs
kubectl logs <pod-name>
```

## Production Benefits
- **Zero downtime deployments**: Old pods finish requests before terminating
- **Data integrity**: All database transactions complete
- **Connection cleanup**: No hanging connections
- **Monitoring**: Clear shutdown logs for debugging

## Configuration
- Default timeout: 30 seconds
- Configurable in `src/index.ts`
- Add custom cleanup in `onShutdown` callback