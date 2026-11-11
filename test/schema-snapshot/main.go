// Temporary one-shot schema capture for consolidating owner migrations.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/pavlith/arc/sdk/database"
	core "github.com/pavlith/arc/services/core/migrations"
	files "github.com/pavlith/arc/services/files/migrations"
	notify "github.com/pavlith/arc/services/notify/migrations"
	pages "github.com/pavlith/arc/services/pages/migrations"
	task "github.com/pavlith/arc/services/task/migrations"
)

type snapshot struct {
	Name   string   `json:"name"`
	Tables []string `json:"tables"`
	Indexes []string `json:"indexes"`
	Triggers []string `json:"triggers"`
	Seeds []string `json:"seeds"`
}

func capture(ctx context.Context, name string, migrations []*gormigrate.Migration) error {
	dir, err := os.MkdirTemp("", "arc-schema-"+name)
	if err != nil { return err }
	defer os.RemoveAll(dir)
	db, err := database.Open(ctx, filepath.Join(dir, "owner.sqlite"))
	if err != nil { return err }
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations); err != nil { return err }
	raw, err := db.DB()
	if err != nil { return err }
	rows, err := raw.QueryContext(ctx, `SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' AND name<>'schema_migrations' ORDER BY type,name`)
	if err != nil { return err }
	out := snapshot{Name: name}
	var names []string
	for rows.Next() {
		var kind, tableName, ddl string
		if err := rows.Scan(&kind,&tableName,&ddl); err != nil { rows.Close(); return err }
		switch kind {
		case "table": out.Tables=append(out.Tables,ddl); names=append(names,tableName)
		case "index": out.Indexes=append(out.Indexes,ddl)
		case "trigger": out.Triggers=append(out.Triggers,ddl)
		default: rows.Close(); return fmt.Errorf("unsupported sqlite object %q %q",kind,tableName)
		}
	}
	if err := rows.Err(); err != nil { rows.Close(); return err }
	rows.Close()
	for _, tbl := range names {
		meta, err := raw.QueryContext(ctx,fmt.Sprintf("PRAGMA table_info(%q)",tbl))
		if err != nil { return err }
		var names []string
		for meta.Next() {
			var cid, notnull, pk int
			var col, typ string
			var def sql.NullString
			if err := meta.Scan(&cid,&col,&typ,&notnull,&def,&pk); err != nil { meta.Close(); return err }
			names=append(names,col)
		}
		if err := meta.Err(); err != nil { meta.Close(); return err }
		meta.Close()
		if len(names)==0 { return fmt.Errorf("no columns in %s",tbl) }
		exprs,quoted:=make([]string,len(names)),make([]string,len(names))
		for i,col:=range names { exprs[i]=fmt.Sprintf("quote(%q)",col);quoted[i]=fmt.Sprintf("%q",col) }
		query:=fmt.Sprintf("SELECT %s FROM %q",strings.Join(exprs," || ',' || "),tbl)
		values,err:=raw.QueryContext(ctx,query)
		if err != nil { return err }
		for values.Next(){
			var v string
			if err:=values.Scan(&v);err!=nil{values.Close();return err}
			out.Seeds=append(out.Seeds,fmt.Sprintf("INSERT INTO %q(%s) VALUES(%s)",tbl,strings.Join(quoted,","),v))
		}
		if err:=values.Err();err!=nil{values.Close();return err}
		values.Close()
	}
	var invalid int
	if err:=raw.QueryRowContext(ctx,"SELECT count(*) FROM pragma_foreign_key_check").Scan(&invalid);err!=nil{return err}
	if invalid!=0{return fmt.Errorf("%s: foreign-key check failed %d",name,invalid)}
	blob,err:=json.Marshal(out)
	if err!=nil{return err}
	// GitHub Actions can truncate long log lines; chunk ASCII JSON deterministically.
	for i,offset:=0,0;offset<len(blob);i,offset=i+1,offset+4000 {
		end:=offset+4000
		if end>len(blob){end=len(blob)}
		fmt.Printf("ARC_SCHEMA_%s_%04d:%s\n",name,i,blob[offset:end])
	}
	fmt.Fprintf(os.Stderr,"Captured %s: %d tables, %d indexes, %d triggers, %d seed rows\n",name,len(out.Tables),len(out.Indexes),len(out.Triggers),len(out.Seeds))
	return nil
}

func main(){
	ctx:=context.Background()
	for _,o:=range []struct{name string; migrations []*gormigrate.Migration}{
		{"core",core.SQLite()},{"task",task.SQLite()},{"notify",notify.SQLite()},{"files",files.SQLite()},{"pages",pages.SQLite()},
	}{
		if err:=capture(ctx,o.name,o.migrations);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
	}
}
