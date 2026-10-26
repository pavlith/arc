-- Service-owned domain schema, replacing legacy combined migration 000005 (never apply both).
CREATE SCHEMA IF NOT EXISTS notifications AUTHORIZATION arc_migrator;
REVOKE ALL ON SCHEMA notifications FROM PUBLIC;
CREATE TABLE notifications.inbox (
 consumer text NOT NULL, event_id uuid NOT NULL, request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 received_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(consumer,event_id)
);
-- Operator-provisioned M0 addressing; event payloads cannot select recipients.
CREATE TABLE notifications.subscriptions (
 workspace_id uuid NOT NULL, acl_root_id uuid NOT NULL, recipient_user_id uuid NOT NULL,
 active boolean NOT NULL DEFAULT true, PRIMARY KEY(workspace_id,acl_root_id,recipient_user_id)
);
CREATE TABLE notifications.notifications (
 id uuid PRIMARY KEY, recipient_user_id uuid NOT NULL, event_id uuid NOT NULL, kind text NOT NULL CHECK(kind='task.created'),
 created_at timestamptz NOT NULL DEFAULT now(), read_at timestamptz,
 UNIQUE(recipient_user_id,event_id,kind)
);
CREATE TABLE notifications.delivery_intents (
 notification_id uuid NOT NULL REFERENCES notifications.notifications(id), recipient_user_id uuid NOT NULL,
 channel text NOT NULL CHECK(channel='fake'), dedup_key text NOT NULL UNIQUE,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0), delivered_at timestamptz,
 PRIMARY KEY(notification_id,recipient_user_id,channel)
);
GRANT USAGE ON SCHEMA notifications TO arc_notifications;
GRANT SELECT,INSERT,UPDATE ON notifications.inbox,notifications.notifications,notifications.delivery_intents TO arc_notifications;
GRANT SELECT ON notifications.subscriptions TO arc_notifications;
