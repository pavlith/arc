// Test/development-only scoped NKeys; never grants domain users admin subjects.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/nats-io/nkeys"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	dir := flag.String("dir", "", "isolated bootstrap directory")
	flag.Parse()
	if e := run(*dir); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(dir string) error {
	file := filepath.Join(dir, "nats-server.conf")
	raw, e := os.ReadFile(file)
	if e != nil {
		return e
	}
	config := string(raw)
	type permission struct {
		name     string
		pub, sub []string
	}
	micro := func(name string) []string {
		a := []string{}
		for _, op := range []string{"PING", "INFO", "STATS"} {
			a = append(a, "$SRV."+op, "$SRV."+op+"."+name, "$SRV."+op+"."+name+".>")
		}
		return a
	}
	control := []string{"ctl.arc.fabric.register", "ctl.arc.fabric.ready", "ctl.arc.fabric.check"}
	roles := []permission{
		{"task", append(append([]string{"_INBOX.>", "rpc.identity.v1.invocations.verify", "rpc.identity.v1.invocations.exchange_service", "rpc.access.v1.check", "rpc.access.v1.grants.add", "rpc.access.v1.grants.revoke", "evt.task.task.created.v1"}, control...), "$JS.API.STREAM.NAMES"), append([]string{"_INBOX.>", "rpc.task.v1.task.create", "rpc.task.v1.roots.grants", "rpc.task.v1.tasks.get", "rpc.task.v1.tasks.list", "ctl.arc.fabric.probe.m006-task"}, micro("task")...)},
		{"notify", append([]string{"_INBOX.>", "rpc.identity.v1.invocations.verify", "ctl.arc.fabric.event_permit", "$JS.API.STREAM.NAMES", "$JS.API.CONSUMER.INFO.TASK.notify-task-created-v1", "$JS.API.CONSUMER.CREATE.TASK.notify-task-created-v1.evt.task.task.created.v1", "$JS.API.CONSUMER.CREATE.TASK.notify-task-created-v1", "$JS.API.CONSUMER.DURABLE.CREATE.TASK.notify-task-created-v1", "$JS.API.CONSUMER.MSG.NEXT.TASK.notify-task-created-v1", "$JS.ACK.TASK.notify-task-created-v1.>", "dlq.evt.task.task.created.v1.notify-task-created-v1"}, control...), append([]string{"_INBOX.>", "rpc.notify.v1.health", "ctl.arc.fabric.probe.m006-notify"}, micro("notify")...)},
	}
	blocks := []string{}
	for _, r := range roles {
		k, e := nkeys.CreateUser()
		if e != nil {
			return e
		}
		seed, e := k.Seed()
		if e != nil {
			return e
		}
		pub, e := k.PublicKey()
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(dir, "nats-"+r.name+".seed"), seed, 0600); e != nil {
			return e
		}
		p, _ := json.Marshal(r.pub)
		s, _ := json.Marshal(r.sub)
		blocks = append(blocks, fmt.Sprintf("{nkey:%q, permissions:{publish:{allow:%s},subscribe:{allow:%s}}}", pub, strings.ReplaceAll(string(p), `\u003e`, ">"), strings.ReplaceAll(string(s), `\u003e`, ">")))
	}
	marker := "  users: ["
	config = strings.Replace(config, marker, marker+"\n"+strings.Join(blocks, ",\n")+",", 1)
	// Core monitoring is separate from both domain identities.
	config = strings.ReplaceAll(config, "\"$SRV.INFO.tasks.>\"", "\"$SRV.INFO.tasks.>\", \"$SRV.INFO.notifications.>\"")
	return os.WriteFile(file, []byte(config), 0600)
}
