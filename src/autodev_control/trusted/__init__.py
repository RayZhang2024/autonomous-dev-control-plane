"""Candidate trusted-core package namespace.

The package bootstrap intentionally performs no imports and exports no broad
fixture or administration surface. Candidate callers import only the exact
trusted submodule/API they require.
"""

__all__: tuple[str, ...] = ()
