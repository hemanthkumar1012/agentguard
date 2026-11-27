.PHONY: help install test bench dev-api dev-web build up down

help:
	@echo "install  - install backend and frontend dependencies"
	@echo "test     - run backend test suite"
	@echo "bench    - regenerate docs/benchmarks.md (traces, detector corpus, latency)"
	@echo "dev-api  - run FastAPI backend with reload"
	@echo "dev-web  - run Next.js console"
	@echo "build    - production build of the frontend"
	@echo "up/down  - start/stop the docker-compose stack"

install:
	cd backend && python -m pip install -e ".[test]"
	cd frontend && npm install

test:
	cd backend && python -m pytest -q

bench:
	cd backend && python -m benchmarks.run --write

dev-api:
	cd backend && uvicorn app.main:app --reload --port 8000

dev-web:
	cd frontend && npm run dev

build:
	cd frontend && npm run build

up:
	docker compose up --build -d

down:
	docker compose down
