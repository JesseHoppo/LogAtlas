export const TEXT_EXTENSIONS = /\.(txt|tsv|csv|json)$/i;

export const FILE_TYPE_PATTERNS = {
  password: {
    patterns: [
      /^passwords?\.(txt|tsv|csv)$/i,
      /^pass(?:words?)?[_-]?(?:list|dump|log)?\.(txt|tsv|csv)$/i,
      /^passwords?[_\s](?:google\s?chrome|microsoft\s?edge|firefox|opera|brave|vivaldi|chromium)[^/]*\.(txt|tsv|csv)$/i,
      /^logins?\.(txt|tsv|csv)$/i,
      /^logins?[_\s][^/]+\.(txt|tsv|csv)$/i,
      /^passwords?[_\s][^/]+\.(txt|tsv|csv)$/i,
      /^credentials?\.(txt|tsv|csv)$/i,
      /^browser[_\s]?passwords?\.(txt|tsv|csv)$/i,
      /^ftps?\.(txt|tsv|csv)$/i,
      /^filezilla\.(txt|tsv|csv)$/i,
      /^brute\.txt$/i,
    ],
    // Aggregate summary files (e.g. `All Passwords.txt`); promoted to real password
    // files by reconcileAggregatePasswordFiles, with dedup at the credential layer.
    aggregatePatterns: [
      /^(?:all|unique|icloud)[\s_-]*passwords?(?:\([^)]+\))?\.(txt|tsv|csv)$/i,
      /^passwords?[\s_-]*(?:unique|all)\.(txt|tsv|csv)$/i,
    ],
    exclusions: [
      /bruteforce/i,
      /wordlist/i,
    ],
    parentDirMatch: /^(?:passwords?|logins|ftps?)$/i,
  },

  cookie: {
    patterns: [
      /^cookies?\.(txt|tsv|csv|json)$/i,
      /^cookies?[\s_-]*dev\.(txt|tsv|csv)$/i,
      /^Cookies[\s_-]*(?:JSON|Netscape)\.txt$/i,
      /^cookies?[\s_][^/]+\.(txt|tsv|csv|json)$/i,
      /^[^/]+[\s_]cookies?\.(txt|tsv|csv|json)$/i,
    ],
    browserProfiles: [
      /^(?:chrome|firefox|edge|opera|brave|vivaldi|chromium)[_\s]?\d+\.txt$/i,
      /^(?:google\s?chrome|microsoft\s?edge)[_\s]?(?:default|profile)?\s*\d*\.txt$/i,
    ],
    textExtensions: TEXT_EXTENSIONS,
    exclusions: [/^cookie[\s_-]*list\.txt$/i, /cookie[\s_-]*restore[\s_-]*data/i],
    excludeFolders: /^(?:auto[\s_-]*fills?|histor(?:y|ies)|downloads?|bookmarks?|passwords?|logins?|credit[\s_-]*cards?)$/i,
    parentDirMatch: /^cookies?$/i,
  },

  sysinfo: {
    filePatterns: [
      /^user[\s_-]*info(?:rmation)?\.txt$/i,
      /^system[\s_-]*info(?:rmation)?\.txt$/i,
      /^sysinfo\.txt$/i,
      /^system\.txt$/i,
      /^info(?:rmation)?\.txt$/i,
      /^_Information\.txt$/i,
      /^information\s*\[[^\]]+\]\.txt$/i,
      /^identification\.txt$/i,
      /^pc[\s_-]*info(?:rmation)?\.(?:txt|json)$/i,
      /^build[\s_-]*info\.txt$/i,
      /^environment\.txt$/i,
    ],
    dirPatterns: [
      /^system$/i,
      /^information$/i,
      /^system\s*info(?:rmation)?$/i,
    ],
  },

  autofill: {
    filePatterns: [
      /^autofills?\.(txt|tsv|csv)$/i,
      /^autofills?_[^/]+\.(txt|tsv|csv)$/i,
      /^browser[\s_-]*autofills?\.(txt|tsv|csv)$/i,
      /^important[\s_-]*autofills?\.(txt|tsv|csv)$/i,
    ],
    folderPattern: /^auto[\s_-]*fills?$/i,
  },

  history: {
    filePatterns: [
      /^history\.(txt|tsv|csv|json)$/i,
      /^browsing[\s_-]*history\.(txt|tsv|csv)$/i,
    ],
    folderPattern: /^(?:browser[\s_-]*)?histor(?:y|ies)$/i,
  },

  bookmark: {
    filePatterns: [
      /^bookmarks?\.(txt|json|html)$/i,
    ],
    folderPattern: /^bookmarks?$/i,
  },

  browserMetadata: {
    filePatterns: [
      /^debug\.txt$/i,
      /^user[\s_-]*agents?(?:\s*\[\d+\])?\.(txt|json)$/i,
      /^(?:user[\s_-]*agent|ua|version|path)\.(txt|json)$/i,
    ],
    folderPatterns: [
      /^path$/i,
      /^ua$/i,
      /^version$/i,
    ],
    pathPatterns: [
      /(^|\/)(?:browser\/)?(?:path|ua|version)\//i,
      /(^|\/)(?:chrome|edge|firefox|opera|brave|vivaldi|chromium)\/debug\.txt$/i,
    ],
  },

  screenshot: {
    namePattern: /(?:^|[\s_-])(?:screenshots?|screen)\b/i,
    extensions: /\.(jpg|jpeg|png|bmp|gif|webp)$/i,
  },

  creditCard: {
    filePatterns: [
      /^(?:credit[\s_-]*)?cards?\.(txt|tsv|csv)$/i,
      /^cc[\s_-]?data\.(txt|tsv|csv)$/i,
      /^CreditCards?\.(txt|tsv|csv)$/i,
      /^[^/]*_cards?\.(txt|tsv|csv)$/i,
    ],
    folderPattern: /^(?:(?:(?:credit|bank)[\s_-]*)?cards?|credits?|cc)$/i,
  },

  cryptoWallet: {
    folderPatterns: [
      /^wallets?$/i,
      /^crypto$/i,
      /^local extension settings$/i,
    ],
    filePatterns: [
      /^wallet[\s_-]*data\.(txt|json)$/i,
      /^keychain(?:\s*data)?\.(txt|tsv|csv)$/i,
      /^metamask/i,
      /^token\.json$/i,
      /^seed\.txt$/i,
      /^data\.json$/i,
    ],
    pathScopedFilePatterns: [
      /^(?:current|lock|log(?:\.old)?|manifest-\d+|\d+\.(?:log|ldb)|.+\.(?:db|sqlite|sqlite3))$/i,
    ],
    pathPatterns: [
      /(^|\/)wallets?\//i,
      /(^|\/)local extension settings\//i,
      /(^|\/)(?:applications|plugins?)\/(?:bitwarden|metamask|phantom|trust wallet|exodus|atomic|keplr|tronlink|ronin|rabby)\//i,
      /(^|\/)(?:bitwarden|metamask|phantom|trust wallet|exodus|atomic|keplr|tronlink|ronin|rabby)\//i,
      /(^|\/)(?:nngceckbapebfimnlniiiahkandclblb|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|acmacodkjbdgmoleebolmdjonilkdbch|dmkamcknogkgcdfhhbddcghachkejeap|ibnejdfjmmkpcnlpebklmnkoeoihofec|fnjhmkhhmkbjkkabndcnnogagogbneec)\//i,
      /(^|\/)extension\/[a-f0-9-]+\/token\.json$/i,
    ],
  },

  accountToken: {
    filePatterns: [
      /^restore_[^/]+\.txt$/i,
      /^googletokens?(?:_[^/]+)?\.txt$/i,
      /^discordtokens?\.txt$/i,
      /^discord\.txt$/i,
      /^token_eaab\.txt$/i,
      /^ids?\.txt$/i,
      /^tokens?\.txt$/i,
      /^steam[\s_-]*tokens?\.txt$/i,
      /^(?:chrome|edge|firefox|opera|brave|vivaldi|chromium|google chrome|microsoft edge)[^/]*\.(txt|json)$/i,
    ],
    folderPatterns: [
      /^googleaccounts$/i,
      /^discord$/i,
      /^steam$/i,
    ],
    pathPatterns: [
      /(^|\/)(?:browser\/)?googleaccounts\//i,
      /(^|\/)accounttokens?\//i,
      /cookie[\s_-]*restore[\s_-]*data[\s_-]*\d*\.txt$/i,
      /(^|\/)restore\/.*token\.txt$/i,
      /(^|\/)browsers?\/token_[^/]+\.txt$/i,
      /(^|\/)fbfastcheck\/(?:token_eaab|ids?)\.txt$/i,
      /(^|\/)(?:applications|games|messengers?|soft)\/discord\/.*(?:discordtokens?|tokens?|discord)\.txt$/i,
      /(^|\/)(?:applications|games|messengers?|soft)\/steam\/.*tokens?\.txt$/i,
    ],
  },

  ftpCredential: {
    filePatterns: [
      /^sitemanager\.xml$/i,
      /^recentservers\.xml$/i,
    ],
    pathPatterns: [
      /(^|\/)filezilla\/[^/]*\.xml$/i,
    ],
  },

  serviceArtifact: {
    filePatterns: [
      /^(?:system|service|user)\.conf$/i,
      /^accounts\.txt$/i,
      /^token\.txt$/i,
      /^usersettings\.json$/i,
      /^\d+\.(?:log|ldb)$/i,
    ],
    pathPatterns: [
      /(^|\/)desktop\/telegram\/token\.txt$/i,
      /(^|\/)(?:applications|soft|messenger)\/anydesk/i,
      /(^|\/)(?:mails?|soft|email clients?)\/outlook/i,
      /(^|\/)outlook - windows app \(new\)\//i,
      /(^|\/)messenger\/discord\/.*leveldb\/.*\.(?:log|ldb)$/i,
      /(^|\/)mails?\/thunderbird\.txt$/i,
    ],
  },

  messenger: {
    filePatterns: [
      /^token[s]?\.txt$/i,
      /^discord[\s_-]*token/i,
      /^accounts\.txt$/i,
      /^Token_EAAB\.txt$/i,
      /^IDs\.txt$/i,
      /^steam[\s_-]*tokens?\.txt$/i,
      /^(?:system|service|user)\.conf$/i,
    ],
  },

  clipboard: {
    filePatterns: [
      /^clipboard\.txt$/i,
    ],
  },

  notes: {
    filePatterns: [
      /^notes?[\s_-]*\d*\.txt$/i,
      /^stickynotes(?:_sqlite)?\.txt$/i,
    ],
    folderPatterns: [
      /^notes?$/i,
      /^stickynotes$/i,
    ],
    pathPatterns: [
      /(^|\/)notes?\//i,
      /(^|\/)stickynotes(?:\/|_sqlite\.txt$)/i,
    ],
  },

  grabbedFiles: {
    folderPatterns: [
      /^filegrabber$/i,
      /^important files$/i,
    ],
    pathPatterns: [
      /(^|\/)filegrabber\//i,
      /(^|\/)important files\//i,
      /(^|\/)files\/(?:desktop|downloads?|documents?)\//i,
    ],
  },

  keylog: {
    pathPatterns: [
      /(^|\/)extension\/[a-f0-9-]+\/\d+\.txt$/i,
    ],
  },

  credits: {
    filePatterns: [
      /^credits?\.txt$/i,
      /^copyright\.txt$/i,
      /^read\s*me\.txt$/i,
    ],
  },

  software: {
    filePatterns: [
      /^installed\s*software(?:\s*\[\d+\])?\.txt$/i,
      /^software(?:\s*\[\d+\])?\.txt$/i,
      /^installed\s*programs?(?:\s*\[\d+\])?\.txt$/i,
      /^programs?\s*list(?:\s*\[\d+\])?\.txt$/i,
      /^installed\s*apps?(?:\s*\[\d+\])?\.txt$/i,
      /^installed\s*browsers?(?:\s*\[\d+\])?\.txt$/i,
    ],
  },

  processList: {
    filePatterns: [
      /^process\s*list(?:\s*\[\d+\])?\.txt$/i,
      /^processes?(?:\s*\[\d+\])?\.txt$/i,
      /^running\s*processes?(?:\s*\[\d+\])?\.txt$/i,
      /^task\s*list(?:\s*\[\d+\])?\.txt$/i,
      /^tasklist(?:\s*\[\d+\])?\.txt$/i,
    ],
  },

  domainDetect: {
    filePatterns: [
      /^domain[\s_-]*detect(?:s)?\.txt$/i,
    ],
  },

  downloadHistory: {
    filePatterns: [
      /^(?:browser[\s_-]*)?downloads?\.(txt|tsv|csv)$/i,
    ],
    folderPattern: /^downloads?$/i,
  },

  browserPlugin: {
    folderPatterns: [
      /^plugins?$/i,
      /^extensions?$/i,
    ],
  },
};
