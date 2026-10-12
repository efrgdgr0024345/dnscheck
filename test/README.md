# Historical upstream diagnostic scripts

This directory preserves Brian Shea's original diagnostic scripts. Some use the
upstream public service domains directly. They are not the isolated regression
suite and are not run by `make test` or the CI workflow.

Before using one for a deployment you control, review its destinations and
traffic pattern and replace every service address with that deployment's test
address. The repeatable local security checks live under `internal/*` and
`tests/`; see [docs/TESTING.md](../docs/TESTING.md).
