package v1

import "github.com/pavlith/arc/sdk/module"

var (
	ListFolders      = module.Query[Scope, FolderList]{ID: "mail.personal.folders.list"}
	GetAccount       = module.Query[Scope, Account]{ID: "mail.personal.accounts.get"}
	UpdateAccount    = module.Command[Update, Account]{ID: "mail.personal.accounts.update"}
	GetCredentialKey = module.Query[Scope, KeyInfo]{ID: "mail.personal.credentials.key"}
	SetCredentials   = module.Command[SetCredential, Account]{ID: "mail.personal.credentials.set"}
	SetAccountState  = module.Command[SetState, Account]{ID: "mail.personal.accounts.state"}
	CheckConnection  = module.Query[Scope, CheckResult]{ID: "mail.personal.accounts.check"}
)
