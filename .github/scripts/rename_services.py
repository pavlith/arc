#!/usr/bin/env python3
"""One-time Arc pre-release service identity and deployment name migration.
Run only against a clean working tree; generated content is reviewed before commit.
"""
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[2]
paths = [p.decode() for p in subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0") if p]
extensions = {".go", ".sql", ".json", ".yaml", ".yml", ".sh", ".md", ".toml", ".py"}
literal = [
    ("notifications-task-created-v1", "notify-task-created-v1"),
    ("arc-notifications", "arc-notify"), ("arc-tasks", "arc-task"),
    ("m006-notifications", "m006-notify"), ("m006-tasks", "m006-task"),
    ("nats-notifications", "nats-notify"), ("nats-tasks", "nats-task"),
    ("postgres_notifications", "postgres_notify"), ("postgres_tasks", "postgres_task"),
    ("postgres-notifications", "postgres-notify"), ("postgres-tasks", "postgres-task"),
    ("arc_notifications", "arc_notify"), ("arc_tasks", "arc_task"),
    ("ARC_TEST_TASKS", "ARC_TEST_TASK"), ("ARC_TASKS", "ARC_TASK"),
    ("NOTIFICATIONS", "NOTIFY"), ("TASKS_DLQ", "TASK_DLQ"),
    ("TASKS", "TASK"),  # Stream, environment and CI labels, not JSON field names
    ("rpc.notifications.v1", "rpc.notify.v1"), ("rpc.tasks.v1", "rpc.task.v1"),
    ("q.notifications.v1", "q.notify.v1"), ("q.tasks.v1", "q.task.v1"),
    ("evt.tasks.", "evt.task."),
    ("tasks.tasks.", "task.tasks."),
    ("tasks.roots.grants", "task.roots.grants"),
    ("tasks.task.created", "task.task.created"),
    ("tasks.workspace", "task.workspace"),
    ("tasks.grants:", "task.grants:"),
    ("notifications.service", "notify.service"),
    ("notifications.health", "notify.health"),
    ("notifications.create", "notify.create"),
    ("notifications.share", "notify.share"),
    ("notifications.delete", "notify.delete"),
    ("tasks.read", "task.read"), ("tasks.create", "task.create"),
    ("tasks.share", "task.share"), ("tasks.delete", "task.delete"),
    ("tasks/v1", "task/v1"), ("notifications/v1", "notify/v1"),
    ("/api/v1/tasks/", "/api/v1/task/"),
    ("/api/v1/notifications/", "/api/v1/notify/"),
    ("sdk/tasks/", "services/task/"), ("sdk/notifications/", "services/notify/"),
    ("services/tasks/", "services/task/"), ("services/notifications/", "services/notify/"),
    ("deploy/tasks/", "deploy/task/"), ("deploy/notifications/", "deploy/notify/"),
    (".secrets/m0-06/tasks", ".secrets/m0-06/task"),
    (".secrets/m0-06/notifications", ".secrets/m0-06/notify"),
    ("tasks_workspace_user", "task_workspace_user"),
    ("tasks_pending_outbox", "task_pending_outbox"),
    ('"tasks"', '"task"'), ('"notifications"', '"notify"'),
    ("'tasks'", "'task'"), ("'notifications'", "'notify'"),
    ("tasksv1", "taskv1"),
    ("notifications.log", "notify.log"),
    ("notifications \"github.com/pavlith/arc/services/notify/modules/inbox\"",
     "notifyinbox \"github.com/pavlith/arc/services/notify/modules/inbox\""),
]
sql_tables = r"roots|tasks|audit|command_results|outbox|inbox|subscriptions|notifications|delivery_intents"
for original in paths:
    if original.startswith((".agents/skills/shadcn-svelte/", ".github/scripts/rename_services.py")):
        continue
    path = root / original
    if path.suffix not in extensions:
        continue
    try:
        source = path.read_text("utf-8")
    except UnicodeError:
        continue
    result = source
    for previous, newer in literal:
        result = result.replace(previous, newer)
    # Rename owner schemas, not plural business tables or Go package selectors.
    result = re.sub(r"\b(tasks|notifications)\.(" + sql_tables + r")\b",
                    lambda m: ("task" if m[1] == "tasks" else "notify") + "." + m[2], result)
    result = re.sub(r"\bSCHEMA (tasks|notifications)\b",
                    lambda m: "SCHEMA " + ("task" if m[1] == "tasks" else "notify"), result)
    result = re.sub(r"\bnotifications\.(Durable|Service|FakeProvider|Effect)\b",
                    r"notifyinbox.\1", result)
    if path.suffix in {".md", ".yaml", ".yml", ".sh"}:
        result = re.sub(r"\bTasks\b", "Task", result)
        result = re.sub(r"\bNotifications\b", "Notify", result)
    if result != source:
        path.write_text(result, encoding="utf-8")
    new = original
    new = new.replace("cmd/arc-tasks/", "cmd/arc-task/")
    new = new.replace("cmd/arc-notifications/", "cmd/arc-notify/")
    new = new.replace("deploy/tasks/", "deploy/task/")
    new = new.replace("deploy/notifications/", "deploy/notify/")
    new = new.replace("services/task/migrations/000001_tasks.up.sql",
                      "services/task/migrations/000001_task.up.sql")
    new = new.replace("services/notify/migrations/000001_notifications.up.sql",
                      "services/notify/migrations/000001_notify.up.sql")
    if new != original:
        dest = root / new
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            raise RuntimeError(f"destination exists: {dest}")
        path.rename(dest)
print("Service identity migration complete", flush=True)
