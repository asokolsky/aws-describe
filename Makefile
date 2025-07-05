# define the name of the virtual environment directory
VENV:=.venv

# targets which are NOT files
.PHONY: help run test clean lint format clean

help:									## Shows the help
	@echo 'Usage: make <TARGETS>'
	@echo ''
	@echo 'Available targets are:'
	@echo ''
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(shell echo "$(MAKEFILE_LIST)" | tr " " "\n" | sort -r | tr "\n" " ") \
		| sed 's/Makefile[a-zA-Z\.]*://' | sed 's/\.\.\///' | sed 's/.*\///' | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ''

run:									## Execute python program
	uv run src/describe.py

test:									## Run unit tests
	uv run -m unittest -v src/*_test.py

lint:									## Lint python sources
# check imports
	uv run ruff check -v --select I src
	uv run ruff check -v src

format:									## Format python sources
# sort imports
	uv run ruff check --select I --fix src
# reformat sources
	uv run ruff format -v src

mypy:									## Check typing
	uv run mypy src

clean:									## Clean up build artifacts
	rm -rf $(VENV) .mypy_cache .ruff_cache
	find . -name __pycache__ | xargs rm -rf
