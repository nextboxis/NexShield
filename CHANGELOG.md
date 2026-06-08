# Changelog

All notable changes to this project will be documented in this file.

## [6.0] - 2026-06-09

### Added
- **Password Change API**: New `/api/auth/change-password` endpoint for authenticated password updates.
- **User Profile API**: New `/api/auth/profile` endpoint returns current user info.
- **Health Check API**: New `/api/health` endpoint for monitoring and readiness checks.
- **Dashboard Summary API**: New `/api/dashboard/summary` combines stats, recent threats, and activity into a single request, reducing network round-trips.
- **Threat Notes**: New `/api/threat/<tid>/notes` endpoint allows analysts to add notes to threats.
- **Bulk Threat Actions**: New `/api/threats/bulk-action` endpoint for acknowledge, dismiss, or escalate operations on multiple threats at once.
- **User Profile Dropdown**: Navbar now shows the logged-in user with logout and password change options.
- **Notification Center**: Real-time notification bell accumulates WebSocket events with unread count badge.
- **Global Search Bar**: Search across threats, hosts, and CVEs from the navigation bar.
- **Skeleton Loading States**: Dashboard shows animated placeholder skeletons during data fetches.
- **Smart Polling**: Auto-refresh pauses when the browser tab is hidden (Page Visibility API).
- **Connection Status Banner**: Visual indicator when WebSocket connection is lost with auto-reconnect.
- **Password Visibility Toggle**: Eye icon on login page to reveal/hide password input.
- **Canvas Particle Background**: Animated cyberpunk particle system on the login page.
- **System Status Indicator**: Login page checks server availability on load.
- **Mobile Hamburger Menu**: Responsive navigation toggle for small screens.
- **Print Stylesheet**: Dashboard and report pages render cleanly for printing.
- **Accessibility**: `prefers-reduced-motion` support, focus-visible styles, keyboard navigation improvements.
- **TinyDB Upsert Support**: `update_one()` now supports `upsert=True` for insert-if-not-found semantics.
- **Tests**: Added route tests (`test_app_routes.py`) and config tests (`test_config.py`).

### Changed
- **Version Bump**: v5.0 → v6.0 across all banners, README, and reports.
- **Dependencies Modernized**: Flask 3.x, scikit-learn 1.5+, numpy 1.26+, pandas 2.2+, pytest 8+, flexible version ranges.
- **UUID4 for Document IDs**: TinyDB wrapper now uses `uuid4` instead of MD5 hash for `_id` generation — eliminates collision risk.
- **HUD Vitals**: Now show actual data (threat counts, WebSocket status) instead of simulated random values.
- **AI Ticker**: Displays real threat summaries instead of random confidence percentages.
- **Stat Box Animations**: Enhanced hover effects with scale and glow micro-interactions.
- **Toast Notifications**: Redesigned with icons, shadows, and improved spacing.

### Fixed
- **Security**: Added missing `@login_required` to `/api/threat/<tid>` and `/api/report/download-rc` endpoints.
- **Security**: Removed plaintext password logging in `run.py` admin provisioning.
- **Security**: Removed pre-filled admin credentials from login page input fields.
- **Security**: Fixed `BaseException` catch in quarantine_host (now catches `Exception` only).
- **Security**: Fixed f-string in logger.error to use lazy `%s` formatting.
- **Bug Fix**: CVE cache writes no longer silently fail when using TinyDB (upsert support added).
- **Bug Fix**: Rate limiter memory cleanup prevents unbounded growth of `_rate_limit_store`.
- **Performance**: Chart canvases now use ResizeObserver instead of debounced window.resize.
- **Performance**: Animation frames pause when tab is hidden (requestAnimationFrame optimization).

### Security
- Account lockout after excessive failed login attempts (enhanced rate limiter).
- Session regeneration on login to prevent session fixation.
- Secure defaults: no pre-filled credentials, no password logging.

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
