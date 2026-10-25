.PHONY: setup dev bootstrap test demo lint down
setup:
	python3 scripts/setup.py
dev: setup
	docker compose up --build -d
bootstrap:
	docker compose exec backend python -m app.cli bootstrap --email $(EMAIL)
demo:
	docker compose exec backend python -m app.cli demo
test:
	cd backend && .venv/bin/python -m pytest -q
	cd frontend && npm run build && npm test
lint:
	cd backend && .venv/bin/ruff check app tests
	cd frontend && npm run lint
down:
	docker compose down
