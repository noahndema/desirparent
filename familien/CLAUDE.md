# CLAUDE.md — DésirParent

## What this app does
DésirParent is a French-language platform for people seeking co-parenting arrangements. Users create profiles, discover potential co-parents, and message each other. Free tier is limited to 5 messages/day; Standard and Premium unlock unlimited messaging with different audience restrictions.

## Stack
Node.js + Express · PostgreSQL (Neon) · Vanilla JS frontend · Deployed on Render

## Directory map
- `server.js` — Legacy monolith: all routes, middleware, business logic (2771 lines — do NOT refactor, do NOT add to)
- `public/` — Static HTML pages served directly (compte.html, messages.html, tarifs.html, etc.)
- `migrations/` — node-pg-migrate migration files, numbered sequentially
- `db/` — Legacy DB helpers (use only for reading; new code goes in backend/src/)
- `services/` — Legacy service files (do not edit)
- `backend/src/` — New TypeScript modules (Polsia conventions, not yet active for this app)

## Database
- `users` — Profiles, auth, subscription fields (subscription_type, plan, subscription_expires_at)
- `messages` — Direct messages between users
- `notifications` — In-app notification records
- `likes` — Profile like/dislike events
- `conversation_notification_flags` — Per-conversation email notification deduplication
- `email_queue` — Async email jobs

## External integrations
- **Stripe** — Two link types: (1) Recurring monthly subscriptions via `create_subscription_link` (9€ Standard, 19€ Premium) with `{CHECKOUT_SESSION_ID}` in success URL; (2) One-time multi-month links. Activation: server-side GET /compte + client-side POST fallback with localStorage persistence.
- **Postmark** — Transactional email (payment confirmation, message notifications)
- **Render** — Hosting; deploys via `push_to_remote`

## Recent changes
- 2026-05-03: Added recurring monthly subscriptions — Standard 9€/month + Premium 19€/month via Polsia Stripe Connect `create_subscription_link`. Plan keys: `standard_recurring`, `premium_recurring`. Featured on tarifs.html as primary CTA. 12-month DB expiry as safety cutoff; Stripe handles auto-billing.
- 2026-05-02: Eliminated 200–400ms navigation lag — added `/api/me` merged endpoint (user + unread counts in one request), sessionStorage caching of auth state (5-min TTL, cleared on logout), unified badge painter that uses cached data instead of refetching, parallelized messages.html init (loadConversations + loadQuota via Promise.all), removed duplicate unread-count fetches from profil.html and decouvrir.html.
- 2026-05-02: Fixed email notification regression — opening a conversation set `updated_at = NOW()` on the notification flag, triggering the "active reader" check and blocking all emails for 10 min. Removed `updated_at` update from flag reset, removed redundant active reader time check (email_notified flag alone handles dedup), added error logging to silent catches.
- 2026-04-30: Fixed subscription activation dead-end — when session lost during Stripe redirect, both server-side GET and client-side POST activation silently failed. Added error logging on server, localStorage persistence on client so pending activation survives login. Manually activated user 74 (noah) Standard subscription.
- 2026-04-30: Fixed subscription activation bug — added server-side activation on GET /compte so subscriptions activate even if client-side JS fails. Fixed misleading "passez Premium" quota message. Manually activated user 1 (jnoah2109@gmail.com) Standard subscription.
