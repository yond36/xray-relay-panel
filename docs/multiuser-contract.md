# Multi-user and core version update contract

Requested behavior: fetch selectable Xray official release versions; permit a manually entered official tag; multiple accounts; administrators see/manage all configurations; registration is administrator-controlled and takes only username and password.

## Ownership and migration

- Roles: admin and user. Existing single administrator and all pre-existing data migrate to one admin identity; preserve account hash, existing configuration, sessions and legacy subscription URL.
- Nodes, upstreams, relays, subscriptions, jobs and probe results carry owner_id. New resources belong to the authenticated actor; updates cannot silently transfer ownership. Administrators can read/manage all existing resources. Regular users read/manage only their own.
- Nodes are private infrastructure, not shared in this update. Non-administrators may add SSH nodes but cannot add the panel's privileged local node. A relay's node and upstream must belong to its owner, including when an administrator edits it. Subscription imports retain the source owner's identity even when refreshed by an administrator.
- Full node application must read complete persistent desired state, never the HTTP user's filtered state, so applying cannot omit active entries because of view filtering.
- Unauthorized object IDs return 404 or 403 without leaking credentials. Node service/log/test/apply/probe, share links, jobs and subscription refresh all enforce ownership. Preserve existing masking.
- Each account has a distinct subscription token. Subscription feeds contain only the token owner's enabled entries, including administrator accounts. The migrated legacy token belongs to the existing administrator and keeps its original personal scope; settings/state must never expose it to another account. Seeing all configurations as an administrator must not automatically expand a previously shared personal subscription URL to other users' proxies.

## HTTP/UI additions

- GET /api/bootstrap adds registration_open and user (id, username, role). Existing initialized/authenticated/version fields remain.
- POST /api/auth/register accepts only username and password, always creates role=user, only while registration_open. Keep first admin setup separate and atomic. Registration defaults closed.
- GET /api/state adds current_user and users (administrator-visible public identities; no hashes/secrets). Existing resource arrays are filtered server-side for non-admins.
- Settings adds registration_open, writable only by administrators; default core_version and panel_url are global administrator settings. The subscription_token in settings is always the current actor's own token; token rotation affects only them.
- GET /api/users lists public users for admins. POST /api/users may create an account while registration is closed (username, password, role); this is admin-only. Any such handler must not expose hashes or raw secrets.
- Frontend shows actual current username/role; offers registration only when open; register form has exactly username and password. Hide admin-only controls from regular users, retain server-side guards. Admin resource lists show owner username. Association pickers use the resource's owner, not the admin's all-users list indiscriminately.

## Core versions

- Authenticated GET /api/core/releases returns {releases:[{tag,name,published_at,prerelease,html_url}], fetched_at, stale, error?}. Official source is https://api.github.com/repos/XTLS/Xray-core/releases . Cache successful responses, bound response/time and redirects, retain stale cache on temporary upstream failure.
- Frontend reusable version picker provides official versions + refresh and custom tag input on nodes and global default settings. Do not automatically apply or upgrade on selection.
- One shared version normalizer/validator accepts an optional v prefix and bounded semantic/date tags with prerelease suffixes, rejects path/URL/shell syntax. Use it in API nodes/settings and engine downloads/core matching. Preserve explicit tag pinning, official assets and checksum validation, no latest fallback.
- Configuration incompatibility fails before switching active service, retaining existing rollback behavior. Use compatibility aliases for common older cores where semantically equivalent; do not silently change an unsupported protocol/transport.

Existing Xray/x-ui isolation is mandatory throughout. Only the dedicated panel and its dedicated node unit may be updated or restarted.
