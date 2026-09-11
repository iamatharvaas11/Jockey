# JOCKY Deployment & Operations Guide

## 1. System Requirements

### Hardware Requirements
* **Minimum:** 2 CPU cores, 4 GB RAM, 20 GB free disk space.
* **Recommended:** 4+ CPU cores, 8+ GB RAM, SSD storage.

### Operating Systems Supported
* **Windows:** Windows 10, Windows 11, Windows Server 2019/2022 (x86_64).
* **Linux:** Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Debian 12 (x86_64, aarch64).

### Core Prerequisites
* Python $\ge$ 3.10 (Python 3.10, 3.11, 3.12, 3.13 supported).
* Optional: C/C++ compiler (`clang` or `gcc`) for standalone native object linking.
* Optional: PostgreSQL $\ge$ 14 for enterprise multi-user production backend.

---

## 2. Installation Procedures

### Windows Installation
1. Clone the repository:
   ```cmd
   git clone <repository_url> jocky
   cd jocky
   ```
2. Create and activate a virtual environment:
   ```cmd
   python -m venv venv
   .\venv\Scripts\activate
   ```
3. Install dependencies in editable mode:
   ```cmd
   pip install -e .[dev,windows]
   ```
4. Verify environment setup:
   ```cmd
   jocky doctor
   ```

### Ubuntu / Linux Installation
1. Clone and enter repository:
   ```bash
   git clone <repository_url> jocky
   cd jocky
   ```
2. Create and activate virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install package and dependencies:
   ```bash
   pip install -e .[dev]
   ```
4. Verify environment setup:
   ```bash
   jocky doctor
   ```

---

## 3. Configuration & Database Setup

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Generate and set a persistent secret key:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(64))"
   ```
3. Database Configuration:
   * **Development (Default):** SQLite `DATABASE_URL=sqlite+aiosqlite:///./jocky.db`
   * **Production:** PostgreSQL `DATABASE_URL=postgresql+asyncpg://jocky_user:StrongPassword@db.internal:5432/jocky_prod`

---

## 4. Starting Central Services

### Starting the Backend & Dashboard Server
Launch the central API and web management console:
```bash
python -m backend.app.main
```
Or using the installed console entrypoint:
```bash
jocky-server
```
The server binds to `0.0.0.0:8000`. Navigate to `http://localhost:8000/dashboard` in a browser.

### First-Run Admin Setup
When starting with an empty database:
1. Navigate to `/register` or perform an authenticated setup request:
   ```bash
   curl -X POST http://localhost:8000/api/v1/auth/setup \
     -H "Content-Type: application/json" \
     -d '{"email": "admin@organization.local", "password": "SecurePassword123!", "full_name": "Security Administrator"}'
   ```
2. Once the first user is initialized as `ADMIN`, the `/setup` endpoint locks automatically and cannot be called again.

---

## 5. Starting Endpoint Agents

To deploy an autonomous agent to an investigation target:
```bash
jocky run examples/runtime/process_scan.jky
```
Or for multi-endpoint centralized monitoring:
1. Configure `AGENT_SERVER_URL=https://central-server:8000` in agent `.env`.
2. Launch agent daemon cycle:
   ```python
   from agent.core import EndpointAgent
   from agent.models import AgentConfig

   agent = EndpointAgent(AgentConfig(hostname="TARGET-HOST-01"))
   # Registers with central server, sends periodic heartbeats, and polls tasks
   ```

---

## 6. Backup & Disaster Recovery

### Database Backup
* **SQLite:** Copy `jocky.db` when the application is idle or use SQLite online backup:
  ```bash
  sqlite3 jocky.db ".backup 'backups/jocky_$(date +%Y%m%d_%H%M%S).db'"
  ```
* **PostgreSQL:**
  ```bash
  pg_dump -U jocky_user -Fc jocky_prod > backups/jocky_prod_$(date +%Y%m%d).dump
  ```

### Evidence & Cryptographic Manifest Backup
All forensic artifacts, JSON evidence exports, and `manifest.json` files in `storage/` and `jocky_output/` are cryptographically verified via Merkle root SHA-256 hashes.
* Store backups on write-once, read-many (WORM) or immutable cloud object storage (e.g. S3 Object Lock).
* Run `jocky verify <backup_path>/manifest.json` to prove evidence integrity before restoring.

