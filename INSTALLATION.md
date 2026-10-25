# Installation on macOS / Linux

Requirements: Git, Docker Engine/Desktop with Compose, and Python 3 for generating private local configuration. Apple Silicon is supported by upstream multi-architecture images. No AWS account or paid API is needed.

```sh
git clone https://github.com/PrathamShah1210/CloudPathX.git
cd CloudPathX
make setup
docker compose up --build -d
make bootstrap EMAIL=you@example.com
make demo
```

Choose a unique password when prompted (12+ characters). Open http://localhost:5173 and sign in. The durable worker processes the synthetic demo. API health is http://localhost:8000/api/v1/health; OpenAPI is at http://localhost:8000/docs. Ports bind only to loopback.

`make setup` generates `.env` with a random database password and private file permissions. It preserves existing configuration. Do not commit `.env`. `make down` stops the stack and preserves the database volume. Never remove that volume unless you intend to delete local data.

## Native development
Use Python 3.12 and Node 22 LTS (the lockfile also builds on newer compatible Node versions).

```sh
cd backend
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
# Set DATABASE_URL to your own local PostgreSQL connection.
.venv/bin/alembic upgrade head
.venv/bin/python -m app.cli bootstrap --email you@example.com
.venv/bin/uvicorn app.main:app --reload
# A second backend terminal with the same DATABASE_URL:
.venv/bin/python -m app.worker
# frontend terminal:
cd frontend
npm ci
npm run dev
```

The Vite proxy targets localhost:8000. In Docker nginx proxies to backend:8000. Tests use isolated SQLite only for API unit tests; actual deployment uses PostgreSQL.

## Verification
```sh
cd backend
.venv/bin/pytest -q --cov=app.engine --cov-report=term-missing --cov-fail-under=85
.venv/bin/ruff check app tests
cd ../frontend
npm ci
npx playwright install chromium
npm run build
npm test
```

See PROGRESS.md for executed tests, environment-specific limitations and the delivered revision.
