# Scaling Plan: Signalix Messenger to ~100k Users

Practical, phased plan for a small team. No enterprise overkill.

---

## 1. Current Bottlenecks (from codebase)

| Area | Current behavior | Becomes a problem when |
|------|------------------|-------------------------|
| **WebSocket** | Single in-memory `Hub` (map userID → conns). All connections on one process. | >1 app instance (e.g. 2nd instance can’t deliver to WS on 1st). Single process limits ~tens of k conns. |
| **Message fanout** | On each message: `ListMembers(convID)` → `BroadcastToUsers(memberIDs, event)`. In-process only. | Large groups (e.g. 100+ members) and/or many concurrent sends. |
| **DB writes** | Every send: 1 INSERT message. `ListMessages` does `MarkIncomingAsRead` (UPDATE) on every open. | High message rate; many users opening chats often. |
| **Unread** | Unread is client-side (chat list context). No server unread table. | Fine until you need server-driven badges; then one more write path. |
| **Conversation list** | `ListConversationsForUser`: 1 query + **N** × `listMembers(convID)` (N = number of convs). Plus for 1:1, N × `GetByID(otherUser)` in handler for `other_avatar_url`. | Many conversations per user (e.g. 50+). |
| **Image uploads** | Local disk: `uploads/images/`, `uploads/audio/`. Single server. | Multi-instance or server replacement; no durability/backup story. |
| **Push** | Expo HTTP in goroutine (non-blocking). Request path still does: ListMembers, GetTokensForUser, sender lookup. | Many recipients per message; token lookup cost. |

---

## 2. Infrastructure and code changes (summary)

- **Redis**: Session/WS routing, optional cache, rate limit state, job queue (later).
- **Background jobs / queue**: Push and heavy fanout off the request path; retries.
- **Object storage**: Replace local uploads with S3-compatible (e.g. MinIO, Cloudflare R2, S3) for images/audio.
- **WebSocket scaling**: Sticky sessions + Redis pub/sub so any app instance can “broadcast” to users on other instances.
- **DB**: Indexes and one or two query changes (conversation list N+1, list messages).
- **Caching**: Optional cache for conversation list or hot reads; not before 10k.
- **Rate limiting / abuse**: Per-user (and optionally per-IP) limits; store in Redis when you have it.

---

## 3. Phased plan

### Phase 1: Up to ~1k users

**Goal:** One server (or 1 app + 1 DB). Stable, observable, no new infra.

- **DB**
  - Add indexes used by hot paths (see checklist).
  - Fix **conversation list N+1**: load members (and optionally other-user avatars) in one or two queries (e.g. batch by conv IDs or join), not per-conversation in a loop.
- **App**
  - Keep single process; ensure connection limits and timeouts (e.g. DB pool, WS write deadline) are set.
  - Add **per-user rate limiting** for send-message (you already have a limiter; ensure it’s enforced and tuned).
  - **Push**: Keep as-is (Expo in goroutine). Optional: move “get tokens + send to Expo” into a small goroutine so request path only enqueues “conv, sender, preview” and returns.
- **Uploads**
  - Keep local disk. Add a simple backup (e.g. cron rsync to another machine or cloud).
- **What you don’t need yet**
  - No Redis, no queue, no object storage, no multi-instance WS, no caching layer.

**Deliverables:** Indexes in place, conversation list query fixed, rate limit and basic observability (logs/metrics) for send and push.

---

### Phase 2: Up to ~10k users

**Goal:** Prepare for horizontal scaling and durability without full rewrites.

- **Redis (single instance)**
  - **WS routing**: When a user connects, register `user_id → instance_id` (e.g. server ID or pod name). On broadcast, only send to local conns; other instances don’t need to be notified for “user on this box” (or use Redis pub/sub so each instance subscribes and forwards to its local conns).
  - **Rate limiting**: Store counters in Redis (per user, optional per IP) for message send, login, etc.
  - Optional: cache conversation list for a short TTL (e.g. 30–60s) keyed by user ID; invalidate on new message in any of user’s convs (or skip cache and rely on DB + indexes).
- **Background jobs**
  - **Push**: Enqueue “new message push” (conv_id, sender_id, preview, exclude_sender) to a queue (Redis List or a small job runner). Worker: resolve members → tokens → call Expo. Request path: write message, broadcast WS, enqueue push job, return.
  - Optional: “broadcast to conversation” job for very large groups (e.g. 50+) so the HTTP request doesn’t do ListMembers + fanout.
- **Object storage**
  - Put new image/audio uploads in S3-compatible storage (R2, MinIO, S3). Store URL in DB. Keep serving existing local files or migrate them later.
- **WebSocket**
  - Run 2+ app instances behind a load balancer with **sticky sessions** (cookie or same IP) so a user’s WS always lands on the same instance. Use Redis so “broadcast to these user IDs” results in in-process send on the instance that holds the connection; if you add pub/sub, other instances publish “user_ids + event” and the instance that has that user sends.
- **DB**
  - Connection pool sizing (e.g. pool size per instance, total connections < Postgres max). Consider read replica only if you see CPU or lock contention on reads.
- **What you don’t need yet**
  - No Kafka, no separate message broker, no Kubernetes, no global cache cluster. No “unread counter” table unless you need server-driven badges.

**Deliverables:** Redis for WS routing + rate limit; push (and optionally large-group fanout) via queue; uploads to object storage; 2+ instances with sticky WS.

---

### Phase 3: Up to ~100k users

**Goal:** Multiple instances, durable workloads, and controlled blast radius.

- **WebSocket**
  - Redis pub/sub (or similar) so every app instance subscribes to a channel (e.g. “ws:broadcast”). On “broadcast to users X,Y,Z”, publisher sends “target user IDs + payload”; each instance forwards only to local connections for those IDs. Single process no longer needs to hold all conns.
- **DB**
  - Read replica(s) for read-heavy endpoints (conversation list, message list, search). Route those reads to replica(s); writes and “read-after-write” to primary.
  - Optional: partition `messages` by `conversation_id` or time if one table gets too large (only if you hit real limits).
- **Push**
  - Same queue; scale workers. Optionally batch Expo calls and handle rate limits / backoff. Consider FCM/APNs direct if you outgrow Expo (later).
- **Caching**
  - Conversation list cache per user (short TTL), invalidate on new message/reaction. Optional: cache “conversation member list” for fanout to avoid DB on every send.
- **Rate limiting / abuse**
  - Redis-backed limits; optional per-IP and per-user; block/list for abusive users; consider captcha or harder checks only if you see abuse.
- **What you still don’t need**
  - No Kafka, no event sourcing, no microservices split, no real-time analytics pipeline. No “unread” table until you need cross-device unread.

**Deliverables:** Multi-instance WS with Redis pub/sub; read replicas; conversation (and optionally member) cache; scaled push workers; abuse controls.

---

## 4. What is NOT needed yet

- **Kafka / RabbitMQ** – Redis list or a simple in-process + Redis queue is enough through 100k.
- **GraphQL / BFF** – REST + WS is fine.
- **Microservices** – One “API + WS” service is enough; push/workers can be separate processes.
- **Kubernetes** – VMs or a simple PaaS (e.g. Fly, Railway, single-tenant) can reach 100k.
- **Dedicated “unread” table** – Until you need server-driven unread badges or sync across devices, client-side unread is acceptable.
- **Full-text search engine (Elasticsearch etc.)** – In-conversation search on `body_preview` with DB indexes is enough for a long time.
- **CDN for API** – Not a scaling requirement at this size; use CDN for static assets/uploads if you want.

---

## 5. Prioritized checklist

**Do first (Phase 1)**  
1. **DB indexes**: You already have `idx_messages_conversation_sent` and `idx_conversation_members_user_id`. Ensure any query used by `ListConversationsForUser` (conversation_members + last message) is covered; add index only if slow.  
2. Remove N+1 in conversation list: load all members (and optionally other-user data for 1:1) in bulk, not per-conversation in a loop.  
3. Ensure message send rate limit is enforced and tuned (e.g. 20/10s per user).  
4. Add minimal observability: logs or metrics for send path, push enqueue/send, and WS broadcast errors.  
5. Document and automate DB backup; optional backup of `uploads/`.

**Phase 2**  
6. Introduce Redis: WS registration (user → instance) and rate limit counters.  
7. Move push off request path: enqueue job (conv, sender, preview), worker calls Expo.  
8. Put new uploads in S3-compatible storage; store URL in DB.  
9. Run 2 app instances with sticky sessions; verify WS and API work.  
10. Tune DB pool and consider read replica only if needed.

**Phase 3**  
11. Redis pub/sub for cross-instance WS broadcast.  
12. Add read replica; route list/search reads to replica.  
13. Optional conversation-list (and member-list) cache with invalidation.  
14. Scale push workers; handle Expo limits.  
15. Harden rate limits and abuse handling (Redis, optional blocklist).

---

## 6. Top 5 things to build next (for scalability)

1. **DB indexes + fix conversation list N+1** – Biggest quick win; reduces load and latency for every chat list load.  
2. **Per-user rate limiting (Redis)** – Prevents a few users from overloading send/push; required before growth.  
3. **Push via queue (Redis list or worker)** – Keeps request path fast and allows retries and backpressure.  
4. **Object storage for new uploads** – Unblocks multi-instance and server replacement; minimal code change (swap write path + URL).  
5. **Sticky sessions + Redis “user → instance”** – Lets you run 2+ instances while WS still works; prerequisite for horizontal scaling.

---

## 7. Keep it practical

- Do Phase 1 with **no new services**. Fix DB and N+1 first; then add Redis and a queue when you approach or pass ~1k users.
- Prefer **one Redis instance** and **one queue pattern** (e.g. Redis List + a worker binary) until you have evidence you need more.
- **Measure** before overbuilding: log p95 for send, list-conversations, and push; add DB slow-query log and connection usage.
- Revisit this plan when you cross ~1k and ~10k active users and adjust phases based on real bottlenecks.
