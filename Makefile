.PHONY: build test lint fmt fmt-check audit check

build:
	cargo build --release

test:
	cargo test --all-targets

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

audit:
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "cargo-audit not installed (install with: cargo install cargo-audit)"; \
	fi

check: fmt-check lint test
