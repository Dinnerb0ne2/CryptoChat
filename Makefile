PYTHON ?= python

.PHONY: install lint type test run-web run-tcp

install:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

type:
	$(PYTHON) -m mypy src

test:
	$(PYTHON) -m pytest

run-web:
	$(PYTHON) -m cryptochat.cli.app server serve-web

run-tcp:
	$(PYTHON) -m cryptochat.cli.app server serve-tcp

