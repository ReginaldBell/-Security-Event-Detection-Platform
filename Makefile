.PHONY: install run test lint frontend build seed scenarios validate

install:
	pip install -r requirements.txt

run:
	uvicorn app.main:app --reload --port 8000

test:
	pytest tests/ -q

lint:
	cd dashboard && npm run lint

frontend:
	cd dashboard && npm run dev

build:
	cd dashboard && npm run build

seed:
	curl -s -X POST http://localhost:8000/incidents/demo-seed | python -m json.tool

scenarios:
	python scenarios/run_scenarios.py

validate:
	python run_validation.py --list

snapshot:
	python scripts/export_openapi_snapshot.py
