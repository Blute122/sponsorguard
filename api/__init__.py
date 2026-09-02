"""Web API layer around the SponsorGuard engine.

Thin FastAPI wrapper: it parses once, runs the existing rule engine, and returns
the scored report plus an `auth_available` flag. No scoring logic lives here —
that stays in the stdlib-only `sponsorguard/` core.
"""
