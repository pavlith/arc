package v1

import "github.com/pavlith/arc/sdk/module"

var (
	RefreshMessageIndex   = module.Command[RefreshMessages, RefreshResult]{ID: "mail.personal.messages.refresh"}
	ListCachedMessages    = module.Query[CachedListQuery, CachedList]{ID: "mail.personal.messages.cached.list"}
	GetCachedMessage      = module.Query[CachedGetQuery, CachedGet]{ID: "mail.personal.messages.cached.get"}
	CreatePersonalAccount = module.Command[CreateAccount, Account]{ID: "mail.personal.accounts.create"}
	ListAccounts          = module.Query[AccountListQuery, AccountList]{ID: "mail.personal.accounts.list"}
	PrivateDownload       = module.Query[DownloadRequest, struct{}]{ID: "mail.personal.messages.download"}
	GetStructure          = module.Query[StructureQuery, Structure]{ID: "mail.personal.messages.structure"}
	ListMessages          = module.Query[MessageListQuery, MessageList]{ID: "mail.personal.messages.list"}
	ListFolders           = module.Query[Scope, FolderList]{ID: "mail.personal.folders.list"}
	GetAccount            = module.Query[Scope, Account]{ID: "mail.personal.accounts.get"}
	UpdateAccount         = module.Command[Update, Account]{ID: "mail.personal.accounts.update"}
	GetCredentialKey      = module.Query[Scope, KeyInfo]{ID: "mail.personal.credentials.key"}
	SetCredentials        = module.Command[SetCredential, Account]{ID: "mail.personal.credentials.set"}
	SetAccountState       = module.Command[SetState, Account]{ID: "mail.personal.accounts.state"}
	CheckConnection       = module.Query[Scope, CheckResult]{ID: "mail.personal.accounts.check"}
)
