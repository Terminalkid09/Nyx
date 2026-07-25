.PHONY: help build-backend build-frontend build-all up up-backend down logs migrate test lint clean

help:
	@echo "Commands:"
	@echo "  build-backend   Build backend Docker image"
	@echo "  build-frontend  Build frontend Docker image"
	@echo "  build-all       Build all Docker images"
	@echo "  up              Start all services (docker compose up -d)"
	@echo "  up-backend      Start only postgres + backend"
	@echo "  down            Stop all services"
	@echo "  logs            View backend logs"
	@echo "  migrate         Run alembic migrations inside backend"
	@echo "  test            Run pytest in backend"
	@echo "  lint            Run ruff check on backend"
	@echo "  clean           Remove all containers and volumes"

build-backend:
	SECRET_KEY=build docker compose build backend

build-frontend:
	docker compose build frontend

build-all: build-backend build-frontend

up:
	@[ -f .env ] && set -a && . ./.env || true; \
	SECRET_KEY=$${SECRET_KEY:-dev-secret} docker compose up -d

up-backend:
	@[ -f .env ] && set -a && . ./.env || true; \
	SECRET_KEY=$${SECRET_KEY:-dev-secret} docker compose up -d postgres backend

down:
	docker compose down -v

logs:
	docker compose logs -f backend

migrate:
	docker compose exec backend alembic upgrade head

test:
	docker compose exec backend python -m pytest tests/ -v

lint:
	docker compose exec backend ruff check .

clean:
	docker compose down -v
	docker system prune -f
