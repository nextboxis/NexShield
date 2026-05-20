# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-05-20

### Added
- Created `msf_utils.py` to centralize Metasploit RC script generation and threat mapping logic.
- Implemented comprehensive `pytest` test suites for core application modules (`ai_logic.py`, `cve_lookup.py`, `scanner.py`).
- Added full Docker support with a `Dockerfile` and `docker-compose.yml` for multi-container orchestration (App, MongoDB, Metasploit).

### Changed
- Refactored `app.py` to use imported Metasploit mapping utilities, reducing hardcoded definitions and duplication.
- Updated `exploit_cli.py` to correctly import Metasploit RC functionality, enforced timeouts on network requests, and added explicit `utf-8` encoding to file I/O operations.
- Modified `msf_rpc.py` to properly capture specific connection exceptions rather than bare broad exceptions, and removed unnecessary imports.
- Re-formatted string interpolations in logging calls to use lazy string formatting for performance.
- Cleaned up control flow in `run.py` to eliminate redundant `else` blocks after `return` statements.

### Fixed
- Addressed various `pylint` warnings (e.g., broad exception handling, bare strings).
- Fixed missing explicit encoding declarations during file reads and writes across several files.
