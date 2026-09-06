# tests/conftest.py
# The files in tests/fixtures/ are sample code for the scanner to analyze,
# not real test modules. Without this, pytest tries to import and execute
# them (because they start with "test_"), which can crash on things like
# subprocess calls or intentionally broken code.

collect_ignore_glob = ["fixtures/*"]