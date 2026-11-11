# Files integration and resource references

Tracking: [#31](https://github.com/pavlith/arc/issues/31). UI remains paused.

## Read authority

A reference is kind + workspace + root + object UUID. Cross-owner reads travel
through exact signed invocation edges, never SQL joins across services. Initial
references preserve the incoming workspace (including empty personal scope);
cross-workspace/personal-to-workspace references are denied. The owner rechecks
session, actual root and current ACL. Lookup returns only title and revision,
not arbitrary stored HTML or an unchecked URL. Missing/denied targets return no
summary; dependency outages fail closed. No external URLs are fetched.

## Task attachments

Task stores up to 100 opaque Files references per work item in its own database.
Attach requires current task.create, source revision/update-time CAS and a fresh
Files metadata read under the same actor. Detach requires source authority and
CAS but may remove an inaccessible/archived target without reading its metadata.
Lists return source-owned opaque references only; they are not evidence of
current target existence. Preview always performs fresh target authorization.
Reference changes increment Task revision and commit history/outbox/replay in
one transaction. Removing a reference does not delete Files bytes. Files archive
hides its metadata/download; retained references can be detached. No implicit
grant, cross-root file move or target title cache is introduced.

## Avatar assets

Files accepts binary or validated PNG/JPEG uploads. Raster files are limited to
4 MiB and 1024×1024 decoded dimensions; full decode must succeed before they
become ready. SVG, HTML and arbitrary URL assets are not accepted. General
content downloads remain attachments. The separately signed image flag enables
`/files/{id}/image` through the same authorized private stream, with exact
PNG/JPEG content type, nosniff, fixed inline name and restrictive CSP.

An owner prepares an avatar through the personal Files `/files/{id}/avatar`
operation. Files verifies the active root's user owner and ready raster asset,
then signs a one-minute user/session-bound receipt. Identity profile update
accepts `avatar_receipt` (omitted preserves, empty clears), verifies the live
Files service/key and signature, and stores only the opaque reference under
profile revision CAS. It never accepts an arbitrary avatar URL. A grantee cannot
prepare another owner's asset. Profile reads return an authorized Files image
path, not a public share: other users need current target read access. A receipt
does not grant target rights; archive/revoke blocks the image immediately on
its next normal authorization check. Replacing/clearing an avatar retains Files
bytes. Receipt issuance/profile commit are separate owner transactions: a race
may leave a stale reference, which cannot expose inaccessible bytes.

Migrations: Task `000009_attachments`; Core `000014_avatar_assets`. Approve the
new producer digests and exact signed read edges before deployment. No automatic
production approval, external HTTP fetch, broad service grant or UI change is
implied.
