// Test/development-only scoped NKeys; never grants domain users admin subjects.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nkeys"
	"github.com/pavlith/arc/sdk/contract"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
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
	taskContract, e := contract.Compile(taskv1.Artifact())
	if e != nil {
		return e
	}
	notifyContract, e := contract.Compile(notifyv1.Artifact())
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
	// RPC listeners get only the subjects defined in their exact compiled
	// contract; the fixture must evolve together with signed installations.
	rpcSubjects := func(m *contract.Compiled) []string {
		subjects := make([]string, 0, len(m.Manifest.Operations))
		for _, op := range m.Manifest.Operations {
			subjects = append(subjects, op.Subject)
		}
		return subjects
	}
	eventSubjects := func(m *contract.Compiled) []string {
		subjects := make([]string, 0, len(m.Manifest.Events))
		for _, event := range m.Manifest.Events {
			subjects = append(subjects, event.Subject)
		}
		return subjects
	}
	control := []string{"ctl.arc.fabric.register", "ctl.arc.fabric.ready", "ctl.arc.fabric.check"}
	taskPub := append([]string{
		"_INBOX.>", "rpc.identity.v1.invocations.verify", "rpc.identity.v1.invocations.exchange_service",
		"rpc.access.v1.check", "rpc.access.v1.check_many", "rpc.access.v1.grants.add",
		"rpc.access.v1.grants.revoke", "$JS.API.STREAM.NAMES",
	}, control...)
	taskPub = append(taskPub, eventSubjects(taskContract)...)
	taskSub := append([]string{"_INBOX.>", "ctl.arc.fabric.probe.m006-task"}, rpcSubjects(taskContract)...)
	taskSub = append(taskSub, micro("task")...)
	notifyPub := append([]string{
		"_INBOX.>", "rpc.identity.v1.invocations.verify", "rpc.identity.v1.invocations.exchange_service",
		"rpc.access.v1.check", "rpc.access.v1.check_many", "ctl.arc.fabric.event_permit",
		"$JS.API.STREAM.NAMES", "$JS.API.CONSUMER.INFO.TASK.notify-task-created-v1",
		"$JS.API.CONSUMER.CREATE.TASK.notify-task-created-v1.evt.task.task.created.v1",
		"$JS.API.CONSUMER.CREATE.TASK.notify-task-created-v1",
		"$JS.API.CONSUMER.DURABLE.CREATE.TASK.notify-task-created-v1",
		"$JS.API.CONSUMER.MSG.NEXT.TASK.notify-task-created-v1",
		"$JS.ACK.TASK.notify-task-created-v1.>", "dlq.evt.task.task.created.v1.notify-task-created-v1",
	}, control...)
	notifyPub = append(notifyPub, eventSubjects(notifyContract)...)
	notifySub := append([]string{"_INBOX.>", "ctl.arc.fabric.probe.m006-notify"}, rpcSubjects(notifyContract)...)
	notifySub = append(notifySub, micro("notify")...)
	roles := []permission{
		{name: "task", pub: taskPub, sub: taskSub},
		{name: "notify", pub: notifyPub, sub: notifySub},
		// Isolated Gate realtime credential has exact read-only event subjects.
		{name: "realtime", pub: []string{"_INBOX.>"}, sub: []string{
			"_INBOX.>", taskv1.CreatedSubject, taskv1.CatalogChangedSubject,
			notifyv1.InboxChangedSubject,
		}},
	}
	blocks := []string{}
	for _, role := range roles {
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
		if e = os.WriteFile(filepath.Join(dir, "nats-"+role.name+".seed"), seed, 0600); e != nil {
			return e
		}
		p, _ := json.Marshal(role.pub)
		s, _ := json.Marshal(role.sub)
		blocks = append(blocks, fmt.Sprintf("{nkey:%q, permissions:{publish:{allow:%s},subscribe:{allow:%s}}}", pub, strings.ReplaceAll(string(p), `\u003e`, ">"), strings.ReplaceAll(string(s), `\u003e`, ">")))
	}
	marker := "  users: ["
	config = strings.Replace(config, marker, marker+"\n"+strings.Join(blocks, ",\n")+",", 1)
	// Core monitoring is separate from both domain identities.
	config = strings.ReplaceAll(config, "\"$SRV.INFO.task.>\"", "\"$SRV.INFO.task.>\", \"$SRV.INFO.notify.>\"")
	return os.WriteFile(file, []byte(config), 0600)
}
