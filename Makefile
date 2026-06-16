.PHONY: web shell clean audit sbom

# Activate venv and run web interface
web:
	@source .venv/bin/activate && python3 -m horus.web --port 8080

# Drop into a shell with venv activated
shell:
	@source .venv/bin/activate && exec /bin/zsh -i

# Clean pycache
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true

# Run pip-audit to check for vulnerable dependencies
audit:
	@source .venv/bin/activate && pip-audit --strict

# Generate a CycloneDX SBOM
sbom:
	@source .venv/bin/activate && cyclonedx-py environment --output-format json --output-file sbom.json
