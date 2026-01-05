# Anonymous Containers

Anonymous Containers is a secure, ephemeral, peer-to-peer chat experiment that runs entirely inside a Docker internal network. Each chat participant lives in an isolated container, generates fresh encryption keys on startup, and automatically destroys itself after 170 seconds.

## Features
- 🔐 End-to-end encrypted chat using ephemeral RSA keys and AES session keys
- 🕸️ Communication isolated to an internal Docker network (`chat_net`)
- ⏱️ Self-destruct timer (default 170 seconds) that removes the running container
- 🧪 FastAPI relay with WebSocket fan-out and zero message persistence
- 🛠️ Optional CLI commands for inspecting peers, TTL, and fingerprints

## Project Layout
```
anonymous-containers/
├── chat_server/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── server.py
├── chat_peer/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── peer.py
├── docker-compose.yml
├── .env
└── README.md
```

## Prerequisites
- Docker Engine 24+
- Docker Compose plugin
- Access to `/var/run/docker.sock` (peer containers call the Docker Engine to self-remove)

> **Security note**: Mounting the Docker socket into containers grants them control over the Docker host. Do not run this setup on production hosts or alongside untrusted workloads.

## Quick Start
1. Build and launch the stack with two sample peers:
   ```bash
   docker compose up --build
   ```
   This starts:
   - `chat_server` — FastAPI relay (internal-only)
   - `chat_peer_alice` and `chat_peer_bob` — interactive peer CLIs

2. Attach to a peer container to chat:
   ```bash
   docker attach anonymous-containers-chat_peer_alice-1
   ```
   (Accept the attached session; `Ctrl+P` followed by `Ctrl+Q` detaches without stopping the container.)

3. Start chatting:
   - Use `/peers` to list available peers and their fingerprints.
   - Send targeted messages with `@bob hello` or broadcast by omitting the prefix.
   - Check remaining lifetime with `/ttl`.
   - Exit cleanly with `/quit` (the container still self-destructs when the timer hits zero).

Both peers will automatically remove themselves after roughly 3 minutes (170 seconds) of uptime. Logs show countdown milestones and self-destruct events.

## Configuration
Environment variables (can be overridden in `.env` or per-service `environment`):
- `USERNAME` — display name for the peer container
- `CHAT_SERVER_URL` — WebSocket URL (default `ws://chat_server:5000/ws`)
- `TTL_SECONDS` — container lifetime (default 170 seconds)

To spin up additional peers:
```bash
docker compose run \
  --name peer_charlie \
  -e USERNAME=charlie \
  -e TTL_SECONDS=300 \
  chat_peer
```

## How It Works
- **Key exchange**: Each peer creates a 2048-bit RSA key pair and broadcasts its public key via the relay. Peers store fingerprints (first 32 hex chars of SHA-256) for verification.
- **Message flow**: The CLI encrypts each outgoing message with a unique AES session key (`Fernet`). The session key is envelope-encrypted with every recipient’s RSA public key. The FastAPI relay only forwards messages; it never decrypts or stores payloads.
- **Ephemeral containers**: A background timer thread prints countdown milestones and, upon expiry, removes the container by calling the Docker Engine (forced stop + deletion) using the mounted Docker socket.

## Troubleshooting
- **No peers listed**: Wait for other peers to broadcast their public keys or ensure they are attached and running.
- **Unable to self-destruct**: Confirm `/var/run/docker.sock` is mounted and the Docker daemon is reachable from within the container.
- **Relay unreachable**: Validate the Docker network is up (`docker network ls | grep chat_net`) and that the server container is healthy.


