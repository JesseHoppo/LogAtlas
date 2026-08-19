// Stealer-family fingerprints used by the classifier.

export const SIGNAL_WEIGHTS = {
  SELF_ID:         10,
  SYSINFO_FILE:    5,
  SYSINFO_KEY:     3,
  SYSINFO_CONTENT: 4,
  FOLDER:          3,
  FILE_PATTERN:    2,
  STRUCTURE:       4,
  ASCII_BANNER:    6,
};

export const CONFIDENCE_THRESHOLDS = {
  min:    0.25,   // below this = no match
  medium: 0.40,   // >= this = "medium"
  high:   0.60,   // >= this = "high"
};

// selfId patterns are matched across sysinfo, credits, clipboard and the
// password/cookie headers. Mark one `scope: 'sysinfo'` where a single token in
// captured victim data — a bookmark title, a cookie domain, a clipboard line —
// would otherwise be enough to name the family. Multi-word brands and banner
// art stay global: those only ever appear in the stealer's own output.
export const SIGNATURES = {
  Vidar: {
    selfId: [
      { pattern: /vidar\s+stealer/i, label: 'Self-ID: Vidar stealer' },
    ],
    sysinfoFile: { pattern: /^information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Country$/i, label: 'Sysinfo key: Country' },
      { pattern: /^City$/i, label: 'Sysinfo key: City' },
      { pattern: /^ZIP$/i, label: 'Sysinfo key: ZIP' },
      { pattern: /^ISP$/i, label: 'Sysinfo key: ISP' },
      { pattern: /^Version$/i, label: 'Sysinfo key: Version' },
      { pattern: /^GUID$/i, label: 'Sysinfo key: GUID' },
      { pattern: /^Work Dir$/i, label: 'Sysinfo key: Work Dir' },
      { pattern: /^MachineID$/i, label: 'Sysinfo key: MachineID' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^Computer Name$/i, label: 'Sysinfo key: Computer Name' },
      { pattern: /^User Name$/i, label: 'Sysinfo key: User Name' },
      { pattern: /^Display Language$/i, label: 'Sysinfo key: Display Language' },
      { pattern: /^Keyboard Languages?$/i, label: 'Sysinfo key: Keyboard Languages' },
    ],
    sysinfoContent: [
      { pattern: /VIDAR/i, label: 'Sysinfo header: VIDAR branding' },
      { pattern: /vidars\.su/i, label: 'Sysinfo content: vidars.su URL' },
      { pattern: /[\u0400-\u04FF]{3,}/u, label: 'Sysinfo content: Cyrillic text' },
      { pattern: /^\s*Version\s*:\s*.+\r?\n\s*Date\s*:\s*.+\r?\n\s*MachineID\s*:/im, label: 'Sysinfo content: Version/Date/MachineID ordering' },
      { pattern: /^\[Hardware\]$/m, label: 'Sysinfo section: [Hardware]' },
      { pattern: /^\[Network\]$/m, label: 'Sysinfo section: [Network]' },
      { pattern: /^\[Processes\]$/m, label: 'Sysinfo section: [Processes]' },
      { pattern: /^\[Software\]$/m, label: 'Sysinfo section: [Software]' },
    ],
    folders: [
      { pattern: /^Autofill$/i, label: 'Folder: Autofill/' },
      { pattern: /^Cookies$/i, label: 'Folder: Cookies/' },
      { pattern: /^History$/i, label: 'Folder: History/' },
      { pattern: /^CC$/i, label: 'Folder: CC/' },
      { pattern: /^Downloads$/i, label: 'Folder: Downloads/' },
      { pattern: /^Plugins$/i, label: 'Folder: Plugins/' },
      { pattern: /^CreditCards$/i, label: 'Folder: CreditCards/' },
      { pattern: /^Soft\/Telegram$/i, label: 'Folder: Soft/Telegram/' },
      { pattern: /^Soft\/Discord$/i, label: 'Folder: Soft/Discord/' },
      { pattern: /^Files\/Desktop$/i, label: 'Folder: Files/Desktop/' },
      { pattern: /^Files\/Documents$/i, label: 'Folder: Files/Documents/' },
    ],
    files: [
      { pattern: /^unique_passwords\.txt$/i, label: 'File: unique_passwords.txt' },
      { pattern: /^domain detect\.txt$/i, label: 'File: domain detect.txt' },
      { pattern: /^screenshot\.jpg$/i, label: 'File: screenshot.jpg' },
      { pattern: /^passwords\.txt$/i, label: 'File: passwords.txt (root)' },
      { pattern: /^outlook\.txt$/i, label: 'File: outlook.txt' },
      { pattern: /^cookie_list\.txt$/i, label: 'File: cookie_list.txt' },
    ],
    structures: [
      {
        test: (dirs, files) => {
          const hasCookiesDir = dirs.some(d => /^Cookies$/i.test(d));
          const noBrowserDir = !dirs.some(d => /^Browser$/i.test(d));
          return hasCookiesDir && noBrowserDir;
        },
        label: 'Structure: flat layout (no Browser/ wrapper)',
      },
    ],
    exclusions: [
      {
        test: ({ ctx }) => /^information\.txt$/i.test(ctx.sysinfoFilename || '') &&
          ((ctx.sysinfoKeys || []).some(k => /^Build$/i.test(k)) || /^\s*Build\s*:/m.test(ctx.sysinfoText || '')),
      },
    ],
  },

  RedLine: {
    selfId: [
      { pattern: /redline\s+stealer/i, label: 'Self-ID: RedLine stealer' },
    ],
    sysinfoFile: { pattern: /^UserInformation\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Build ID$/i, label: 'Sysinfo key: Build ID' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^Log date$/i, label: 'Sysinfo key: Log date' },
      { pattern: /^Current Language$/i, label: 'Sysinfo key: Current Language' },
      { pattern: /^Operation System$/i, label: 'Sysinfo key: Operation System' },
      { pattern: /^UAC$/i, label: 'Sysinfo key: UAC' },
      { pattern: /^Process Elevation$/i, label: 'Sysinfo key: Process Elevation' },
    ],
    sysinfoContent: [
      { pattern: /^ScreenSize:\s*\{Width=/m, label: 'Sysinfo content: ScreenSize {Width=...}' },
      { pattern: /^UAC:\s*/m, label: 'Sysinfo content: UAC field' },
      { pattern: /^Process Elevation:\s*/m, label: 'Sysinfo content: Process Elevation field' },
    ],
    asciiBanners: [
      '* ____ _____ ____ _ ___ _ _ _____ *',
      '* | _ \\|_____| _ \\',
    ],
    folders: [
      { pattern: /^Autofills$/i, label: 'Folder: Autofills/' },
      { pattern: /^Cookies$/i, label: 'Folder: Cookies/' },
    ],
    files: [
      { pattern: /^-+000\.txt$/i, label: 'File: -----000.txt branding file' },
      { pattern: /^DomainDetects\.txt$/i, label: 'File: DomainDetects.txt' },
      { pattern: /^ImportantAutofills\.txt$/i, label: 'File: ImportantAutofills.txt' },
      { pattern: /^InstalledBrowsers\.txt$/i, label: 'File: InstalledBrowsers.txt' },
      { pattern: /^InstalledSoftware\.txt$/i, label: 'File: InstalledSoftware.txt' },
      { pattern: /^ProcessList\.txt$/i, label: 'File: ProcessList.txt' },
      { pattern: /^Screenshot\.jpg$/i, label: 'File: Screenshot.jpg' },
    ],
    structures: [
      {
        test: (dirs) => {
          const hasAutofills = dirs.some(d => /^Autofills$/i.test(d));
          const hasCookies = dirs.some(d => /^Cookies$/i.test(d));
          const noBrowserWrapper = !dirs.some(d => /^Browser(?:\/|$)/i.test(d));
          return (hasAutofills || hasCookies) && noBrowserWrapper;
        },
        label: 'Structure: top-level Autofills/Cookies without Browser/ wrapper',
      },
      {
        test: (dirs, files) => {
          return files.some(f => /^[^/]+_\[[^\]]+\]_[^/]+\.txt$/i.test(f));
        },
        label: 'Structure: Vendor_[Browser]_Profile.txt naming',
      },
    ],
    exclusions: [
      {
        test: ({ ctx }) => (ctx.sysinfoKeys || []).some(k => /^(Traffic Name|Wallpaper Hash|Product Key)$/i.test(k)),
      },
      {
        test: ({ ctx }) => /ScreenSize:\s*\{Width\s*=\s*[^}]+\}TimeZone:/i.test(ctx.sysinfoText || ''),
      },
    ],
  },

  Rhadamanthys: {
    selfId: [
      { pattern: /rhadamanthys/i, label: 'Self-ID: Rhadamanthys', scope: 'sysinfo' },
    ],
    sysinfoFile: { pattern: /^(?:UserInformation|system)\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Install Date$/i, label: 'Sysinfo key: Install Date' },
      { pattern: /^Traffic Name$/i, label: 'Sysinfo key: Traffic Name' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^User Name$/i, label: 'Sysinfo key: User Name' },
      { pattern: /^Computer Name$/i, label: 'Sysinfo key: Computer Name' },
      { pattern: /^Domain Name$/i, label: 'Sysinfo key: Domain Name' },
      { pattern: /^Wallpaper Hash$/i, label: 'Sysinfo key: Wallpaper Hash' },
      { pattern: /^Product Key$/i, label: 'Sysinfo key: Product Key' },
      { pattern: /^MachineID$/i, label: 'Sysinfo key: MachineID' },
      { pattern: /^Log date$/i, label: 'Sysinfo key: Log date' },
    ],
    sysinfoContent: [
      { pattern: /^now:\s*@/m, label: 'Sysinfo content: Telegram handle (now: @...)' },
      { pattern: /russia34\.com/i, label: 'Sysinfo content: russia34.com' },
      { pattern: /MetaMask Info:/i, label: 'Sysinfo content: MetaMask Info block' },
    ],
    folders: [
      { pattern: /^Browser\/FingerPrint$/i, label: 'Folder: Browser/FingerPrint/' },
      { pattern: /^Browser\/MasterKeys$/i, label: 'Folder: Browser/MasterKeys/' },
      { pattern: /^Browser\/UA$/i, label: 'Folder: Browser/UA/' },
      { pattern: /^Browser\/Path$/i, label: 'Folder: Browser/Path/' },
      { pattern: /^Browser\/Version$/i, label: 'Folder: Browser/Version/' },
      { pattern: /^Browser\/Logins$/i, label: 'Folder: Browser/Logins/' },
      { pattern: /^Browser\/Credits$/i, label: 'Folder: Browser/Credits/' },
      { pattern: /^Browser\/Download$/i, label: 'Folder: Browser/Download/' },
      { pattern: /^Browser\/Bookmarks$/i, label: 'Folder: Browser/Bookmarks/' },
      { pattern: /^Extension$/i, label: 'Folder: Extension/' },
    ],
    files: [
      { pattern: /^DomainDetects\.txt$/i, label: 'File: DomainDetects.txt' },
      { pattern: /^keychain\.txt$/i, label: 'File: keychain.txt (macOS)' },
      { pattern: /^GoogleTokens\.txt$/i, label: 'File: GoogleTokens.txt' },
      { pattern: /^Cards\.txt$/i, label: 'File: Cards.txt' },
      { pattern: /^Brute\.txt$/i, label: 'File: Brute.txt' },
      { pattern: /^Environment\.txt$/i, label: 'File: Environment.txt' },
      { pattern: /^CreditCards\.txt$/i, label: 'File: CreditCards.txt' },
    ],
    structures: [
      {
        test: (dirs) => {
          const hasFingerPrint = dirs.some(d => /^Browser\/FingerPrint$/i.test(d));
          const hasMasterKeys = dirs.some(d => /^Browser\/MasterKeys$/i.test(d));
          return hasFingerPrint || hasMasterKeys;
        },
        label: 'Structure: Browser/FingerPrint or Browser/MasterKeys present',
      },
      {
        test: (dirs, files) => {
          return files.some(f => /^Extension\/[^/]+\/token\.json$/i.test(f));
        },
        label: 'Structure: Extension/{UUID}/token.json',
      },
    ],
    require: ({ matchedCounts }) =>
      matchedCounts.selfId > 0 || matchedCounts.sysinfoContent > 0 ||
      matchedCounts.folder > 0 || matchedCounts.structure > 0,
  },

  Lumma: {
    selfId: [
      { pattern: /lummac2/i, label: 'Self-ID: LummaC2' },
      { pattern: /lumma\s+stealer/i, label: 'Self-ID: Lumma stealer' },
      { pattern: /lumma\s*id/i, label: 'Self-ID: Lumma ID' },
    ],
    sysinfoFile: { pattern: /^System\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^LummaC2(?:,\s*| )Build$/i, label: 'Sysinfo key: LummaC2 Build' },
      { pattern: /^LID(?:\s*\(Lumma ID\))?$/i, label: 'Sysinfo key: LID' },
      { pattern: /^Configuration$/i, label: 'Sysinfo key: Configuration' },
      { pattern: /^Local Date$/i, label: 'Sysinfo key: Local Date' },
      { pattern: /^Elevated$/i, label: 'Sysinfo key: Elevated' },
      { pattern: /^NetBIOS$/i, label: 'Sysinfo key: NetBIOS' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^Screen resolution$/i, label: 'Sysinfo key: Screen resolution' },
    ],
    sysinfoContent: [
      { pattern: /LummaC2/i, label: 'Sysinfo content: LummaC2 branding' },
      { pattern: /^\s*-?\s*LID\s*[:(]/im, label: 'Sysinfo content: LID field' },
      { pattern: /@lummanowork/i, label: 'Sysinfo content: @lummanowork contact' },
      { pattern: /lummamarketplace/i, label: 'Sysinfo content: lummamarketplace' },
      { pattern: /\(sig:[0-9a-f]+\.[0-9a-f]+\)/i, label: 'Sysinfo content: Time with (sig:...) hash' },
    ],
    folders: [
      { pattern: /^Chrome$/i, label: 'Folder: Chrome/' },
      { pattern: /^Edge$/i, label: 'Folder: Edge/' },
      { pattern: /^Cookies$/i, label: 'Folder: Cookies/' },
      { pattern: /^GoogleAccounts$/i, label: 'Folder: GoogleAccounts/' },
      { pattern: /^Applications$/i, label: 'Folder: Applications/' },
      { pattern: /^Wallets$/i, label: 'Folder: Wallets/' },
      { pattern: /^Important Files$/i, label: 'Folder: Important Files/' },
    ],
    files: [
      { pattern: /^All Passwords\.txt$/i, label: 'File: All Passwords.txt' },
      { pattern: /^Brute\.txt$/i, label: 'File: Brute.txt' },
      { pattern: /^Clipboard\.txt$/i, label: 'File: Clipboard.txt' },
      { pattern: /^DomainDetect\.txt$/i, label: 'File: DomainDetect.txt' },
      { pattern: /^Software\.txt$/i, label: 'File: Software.txt' },
      { pattern: /^Processes\.txt$/i, label: 'File: Processes.txt' },
      { pattern: /^Screen\.png$/i, label: 'File: Screen.png' },
    ],
    structures: [
      {
        test: (dirs) => {
          return dirs.some(d => /^Chrome\/[^/]+$/i.test(d)) ||
                 dirs.some(d => /^Edge\/[^/]+$/i.test(d));
        },
        label: 'Structure: Chrome/Edge as top-level dirs with profiles',
      },
      {
        test: (dirs, files) => {
          return files.some(f => /^(?:Chrome|Edge|Firefox|Opera|Brave)\/Debug\.txt$/i.test(f));
        },
        label: 'Structure: Debug.txt inside browser dirs',
      },
      {
        test: (dirs, files) => {
          return files.some(f => /^Cookies\/Cookies_/i.test(f));
        },
        label: 'Structure: Cookies/Cookies_{Browser}_{Profile}.txt',
      },
      {
        test: (dirs, files) => {
          return files.some(f => /^GoogleAccounts\/Restore_/i.test(f));
        },
        label: 'Structure: GoogleAccounts/Restore_{Browser}_{Profile}.txt',
      },
      {
        test: (dirs, files) => {
          return files.some(f => /^(?:Chrome|Edge|Firefox|Opera|Brave|Chromium)\/[^/]+\/dp\.txt$/i.test(f));
        },
        label: 'Structure: dp.txt inside browser directory',
      },
    ],
  },

  Astris: {
    sysinfoFile: { pattern: /^Information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Build$/i, label: 'Sysinfo key: Build' },
      { pattern: /^Public IP Address$/i, label: 'Sysinfo key: Public IP Address' },
      { pattern: /^Internet Provider$/i, label: 'Sysinfo key: Internet Provider' },
      { pattern: /^Product Key$/i, label: 'Sysinfo key: Product Key' },
      { pattern: /^Antiviruses$/i, label: 'Sysinfo key: Antiviruses' },
    ],
    sysinfoContent: [
      { pattern: /^\[General\]$/m, label: 'Sysinfo section: [General]' },
      { pattern: /^\[Machine\]$/m, label: 'Sysinfo section: [Machine]' },
      { pattern: /^\[Network\]$/m, label: 'Sysinfo section: [Network]' },
      { pattern: /^\[Hardware\]$/m, label: 'Sysinfo section: [Hardware]' },
    ],
    folders: [],
    files: [],
    structures: [],
  },

  StealC: {
    selfId: [
      { pattern: /stealc\s+stealer/i, label: 'Self-ID: Stealc stealer' },
      { pattern: /STEALC/i, label: 'Self-ID: STEALC branding', scope: 'sysinfo' },
    ],
    sysinfoFile: { pattern: /^(?:Info|system_info)\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Build Date$/i, label: 'Sysinfo key: Build Date' },
      { pattern: /^Elevated$/i, label: 'Sysinfo key: Elevated' },
      { pattern: /^Netbios$/i, label: 'Sysinfo key: Netbios' },
      { pattern: /^Execution Path$/i, label: 'Sysinfo key: Execution Path' },
      { pattern: /^Running Path$/i, label: 'Sysinfo key: Running Path' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^UserName$/i, label: 'Sysinfo key: UserName' },
      { pattern: /^Cores$/i, label: 'Sysinfo key: Cores' },
      { pattern: /^Display Resolution$/i, label: 'Sysinfo key: Display Resolution' },
      { pattern: /^Laptop$/i, label: 'Sysinfo key: Laptop' },
      { pattern: /^Build ID$/i, label: 'Sysinfo key: Build ID' },
    ],
    sysinfoContent: [
      { pattern: /^Network Info:$/m, label: 'Sysinfo section: Network Info' },
      { pattern: /^System Summary:$/m, label: 'Sysinfo section: System Summary' },
      { pattern: /\(sig:[0-9a-f]+\.[0-9a-f]+\)/i, label: 'Sysinfo content: Time with (sig:...) hash' },
      { pattern: /forum\.exploit\.in/i, label: 'Sysinfo content: exploit.in forum URL' },
      { pattern: /xss\.is/i, label: 'Sysinfo content: xss.is forum URL' },
    ],
    asciiBanners: [
      '______ ______ ______ ______ __ ______',
      '/\\ ___\\/\\ __',
    ],
    folders: [
      { pattern: /^cookies$/i, label: 'Folder: cookies/' },
      { pattern: /^autofill$/i, label: 'Folder: autofill/' },
      { pattern: /^history$/i, label: 'Folder: history/' },
      { pattern: /^AccountTokens$/i, label: 'Folder: AccountTokens/' },
    ],
    files: [
      { pattern: /^All Passwords\.txt$/i, label: 'File: All Passwords.txt' },
      { pattern: /^passwords\.txt$/i, label: 'File: passwords.txt' },
      { pattern: /^Screenshot\.png$/i, label: 'File: Screenshot.png' },
      { pattern: /^screenshot\.jpg$/i, label: 'File: screenshot.jpg' },
      { pattern: /^DomainDetect\.txt$/i, label: 'File: DomainDetect.txt (singular)' },
      { pattern: /^Software\.txt$/i, label: 'File: Software.txt' },
      { pattern: /^Processes\.txt$/i, label: 'File: Processes.txt' },
      { pattern: /^cookie_list\.txt$/i, label: 'File: cookie_list.txt' },
    ],
    structures: [
      {
        test: (dirs) => {
          return dirs.some(d => /^Chrome\/[^/]+$/i.test(d)) ||
                 dirs.some(d => /^Edge\/[^/]+$/i.test(d));
        },
        label: 'Structure: Chrome/Edge as top-level dirs with profiles',
      },
      {
        test: (dirs, files) => {
          return files.some(f => /^(?:Chrome|Edge|Firefox|Opera|Brave)\/Debug\.txt$/i.test(f));
        },
        label: 'Structure: Debug.txt inside browser dirs',
      },
      {
        test: (dirs, files) => {
          return files.some(f => /^Cookies\/Cookies_/i.test(f));
        },
        label: 'Structure: Cookies/Cookies_{Browser}_{Profile}.txt',
      },
      {
        test: (dirs, files) => {
          return files.some(f => /^GoogleAccounts\/Restore_/i.test(f));
        },
        label: 'Structure: GoogleAccounts/Restore_{Browser}_{Profile}.txt',
      },
      {
        test: (dirs, files) => {
          // v2 layout: cookie files named with UUIDs
          return files.some(f => /^cookies\/cookie_[0-9a-f]{8}-/i.test(f));
        },
        label: 'Structure: cookies/cookie_{UUID}.txt (v2 layout)',
      },
    ],
  },

  // A log shop, not a stealer. Its banner is stamped over whatever family
  // actually ran, so it is scored like any other signature but reported as the
  // distributor rather than as the family.
  Ottoman: {
    kind: 'reseller',
    selfId: [
      { pattern: /\(\s*O\s*\|\s*T\s*\|\s*T\s*\|\s*O\s*\|\s*M\s*\|\s*A\s*\|\s*N\s*\)/i, label: 'Self-ID: OTTOMAN banner' },
      { pattern: /ottoman\s*cl[oó]ud/i, label: 'Self-ID: OTTOMAN CLOUD' },
      { pattern: /@salesupports/i, label: 'Self-ID: @salesupports resale handle' },
      { pattern: /\bottoman\b/i, label: 'Self-ID: OTTOMAN brand', scope: 'sysinfo' },
    ],
    sysinfoFile: { pattern: /^(?:information|UserInformation|system_info|SystemInformation|Info|System)\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Version$/i, label: 'Sysinfo key: Version' },
      { pattern: /^Work Dir$/i, label: 'Sysinfo key: Work Dir' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^Build ID$/i, label: 'Sysinfo key: Build ID' },
    ],
    sysinfoContent: [
      { pattern: /@salesupports/i, label: 'Sysinfo content: @salesupports' },
      { pattern: /Buy daily fresh logs/i, label: 'Sysinfo content: resale tagline' },
    ],
    folders: [
      { pattern: /^Autofill$/i, label: 'Folder: Autofill/' },
      { pattern: /^Cookies$/i, label: 'Folder: Cookies/' },
      { pattern: /^History$/i, label: 'Folder: History/' },
      { pattern: /^GoogleAccounts$/i, label: 'Folder: GoogleAccounts/' },
    ],
    files: [
      { pattern: /^unique_passwords\.txt$/i, label: 'File: unique_passwords.txt' },
      { pattern: /^domain detect\.txt$/i, label: 'File: domain detect.txt' },
      { pattern: /^All Passwords\.txt$/i, label: 'File: All Passwords.txt' },
    ],
    structures: [],
  },

  Raccoon: {
    selfId: [
      { pattern: /raccoon\s+stealer/i, label: 'Self-ID: Raccoon stealer' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Computer\s*Name$/i, label: 'Sysinfo key: Computer Name' },
      { pattern: /^User\s*Name$/i, label: 'Sysinfo key: User Name' },
      { pattern: /^OS\s*Version$/i, label: 'Sysinfo key: OS Version' },
      { pattern: /^IP\s*Address$/i, label: 'Sysinfo key: IP Address' },
      { pattern: /^Tracker$/i, label: 'Sysinfo key: Tracker' },
      { pattern: /^Bot_ID$/i, label: 'Sysinfo key: Bot_ID' },
      { pattern: /^Launched at$/i, label: 'Sysinfo key: Launched at' },
      { pattern: /^Build compile date$/i, label: 'Sysinfo key: Build compile date' },
    ],
    sysinfoContent: [
      { pattern: /Raccoon/i, label: 'Sysinfo content: Raccoon branding' },
    ],
    asciiBanners: [
      '\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2584\u2584\u2584\u2584\u2584\u2584\u2584',
    ],
    folders: [
      { pattern: /^Browser$/i, label: 'Folder: Browser/' },
      { pattern: /^Browser\/Passwords$/i, label: 'Folder: Browser/Passwords/' },
      { pattern: /^Browser\/Cookies$/i, label: 'Folder: Browser/Cookies/' },
      { pattern: /^Browser\/History$/i, label: 'Folder: Browser/History/' },
    ],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
      { pattern: /^Screenshot\.png$/i, label: 'File: Screenshot.png' },
    ],
    structures: [
      {
        test: (dirs) => {
          const hasBrowser = dirs.some(d => /^Browser$/i.test(d));
          const hasBrowserPasswords = dirs.some(d => /^Browser\/Passwords$/i.test(d));
          const hasBrowserCookies = dirs.some(d => /^Browser\/Cookies$/i.test(d));
          return hasBrowser && hasBrowserPasswords && hasBrowserCookies;
        },
        label: 'Structure: Browser/ with Passwords/ and Cookies/ subdirs',
      },
    ],
  },

  Raccoon2: {
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^User ID$/i, label: 'Sysinfo key: User ID' },
      { pattern: /^Last seen$/i, label: 'Sysinfo key: Last seen' },
      { pattern: /^Build$/i, label: 'Sysinfo key: Build' },
      { pattern: /^IP info$/i, label: 'Sysinfo key: IP info' },
      { pattern: /^Installed applications$/i, label: 'Sysinfo key: Installed applications' },
    ],
    sysinfoContent: [
      { pattern: /^System Information:\s*$/m, label: 'Sysinfo section: System Information' },
    ],
    folders: [],
    files: [],
    structures: [],
  },

  RisePro: {
    selfId: [
      { pattern: /risepro/i, label: 'Self-ID: RisePro', scope: 'sysinfo' },
    ],
    sysinfoFile: { pattern: /^information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Build$/i, label: 'Sysinfo key: Build' },
      { pattern: /^Version$/i, label: 'Sysinfo key: Version' },
      { pattern: /^MachineID$/i, label: 'Sysinfo key: MachineID' },
      { pattern: /^GUID$/i, label: 'Sysinfo key: GUID' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^IP$/i, label: 'Sysinfo key: IP' },
    ],
    sysinfoContent: [
      { pattern: /RisePro/i, label: 'Sysinfo content: RisePro branding' },
      { pattern: /^\s*Build\s*:\s*.+\r?\n\s*Version\s*:/im, label: 'Sysinfo content: Build before Version' },
      { pattern: /^\[Hardware\]$/m, label: 'Sysinfo section: [Hardware]' },
      { pattern: /^\[Processes\]$/m, label: 'Sysinfo section: [Processes]' },
    ],
    folders: [
      { pattern: /^Browser$/i, label: 'Folder: Browser/' },
      { pattern: /^Wallets$/i, label: 'Folder: Wallets/' },
      { pattern: /^Extensions$/i, label: 'Folder: Extensions/' },
      { pattern: /^FileGrabber$/i, label: 'Folder: FileGrabber/' },
    ],
    files: [
      { pattern: /^InstalledBrowsers\.txt$/i, label: 'File: InstalledBrowsers.txt' },
      { pattern: /^InstalledSoftware\.txt$/i, label: 'File: InstalledSoftware.txt' },
      { pattern: /^Screenshot\.png$/i, label: 'File: Screenshot.png' },
    ],
    structures: [
      {
        test: (dirs) => {
          const hasWallets = dirs.some(d => /^Wallets$/i.test(d));
          const hasExtensions = dirs.some(d => /^Extensions$/i.test(d));
          return hasWallets && hasExtensions;
        },
        label: 'Structure: Wallets/ + Extensions/ present',
      },
    ],
    require: ({ ctx, matchedCounts }) => {
      return matchedCounts.selfId > 0 ||
        (ctx.sysinfoKeys || []).some(k => /^Build$/i.test(k)) ||
        /^\s*Build\s*:\s*.+\r?\n\s*Version\s*:/im.test(ctx.sysinfoText || '');
    },
  },

  Atomic: {
    osClass: 'macos',
    selfId: [
      { pattern: /atomic\s*stealer/i, label: 'Self-ID: Atomic Stealer' },
      { pattern: /\bamos\b/i, label: 'Self-ID: AMOS (Atomic macOS Stealer)', scope: 'sysinfo' },
    ],
    sysinfoFile: { pattern: /^Sysinfo\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Chip$/i, label: 'Sysinfo key: Chip' },
      { pattern: /^ProductName$/i, label: 'Sysinfo key: ProductName' },
      { pattern: /^ProductVersion$/i, label: 'Sysinfo key: ProductVersion' },
      { pattern: /^BuildVersion$/i, label: 'Sysinfo key: BuildVersion' },
      { pattern: /^Hardware\s*UUID$/i, label: 'Sysinfo key: Hardware UUID' },
    ],
    sysinfoContent: [
      { pattern: /^Hardware Overview:/m, label: 'Sysinfo content: Hardware Overview section' },
      { pattern: /^ProductName:\s*/m, label: 'Sysinfo content: sw_vers ProductName' },
      { pattern: /^BuildVersion:\s*/m, label: 'Sysinfo content: sw_vers BuildVersion' },
      { pattern: /\b(?:MacBook|Apple M|Retina)\b/i, label: 'Sysinfo content: macOS hardware reference' },
    ],
    folders: [
      { pattern: /^FileGrabber$/i, label: 'Folder: FileGrabber/' },
      { pattern: /^Keychains?$/i, label: 'Folder: Keychain/' },
      { pattern: /^Browsers$/i, label: 'Folder: Browsers/' },
    ],
    files: [
      { pattern: /^keychain\.txt$/i, label: 'File: keychain.txt' },
      { pattern: /^Note\.txt$/i, label: 'File: Note.txt' },
      { pattern: /^CreditCards\.txt$/i, label: 'File: CreditCards.txt' },
    ],
    structures: [
      {
        test: (dirs) => {
          const hasKeychain = dirs.some(d => /^Keychains?$/i.test(d));
          const hasFileGrabber = dirs.some(d => /^FileGrabber$/i.test(d));
          return hasKeychain || hasFileGrabber;
        },
        label: 'Structure: Keychain/ or FileGrabber/ (macOS stealer)',
      },
    ],
    require: ({ matchedCounts }) =>
      matchedCounts.selfId > 0 || matchedCounts.sysinfoContent > 0 || matchedCounts.sysinfoKey > 0,
    exclusions: [
      {
        test: ({ ctx }) => /\bWindows\b/i.test(ctx.sysinfoText || ctx.combinedSysinfoText || ''),
      },
    ],
  },

  META: {
    selfId: [
      { pattern: /meta\s+stealer/i, label: 'Self-ID: META stealer' },
    ],
    sysinfoFile: { pattern: /^UserInformation\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [],
    sysinfoContent: [
      { pattern: /\(\s*M\s*\|\s*E\s*\|\s*T\s*\|\s*A\s*\)/, label: 'Sysinfo content: META ASCII banner' },
    ],
    asciiBanners: [
      '( M | E | T | A )',
    ],
    folders: [],
    files: [],
    structures: [],
    require: ({ matchedCounts }) => matchedCounts.selfId > 0 || matchedCounts.sysinfoContent > 0 || matchedCounts.asciiBanner > 0,
  },

  CryptBot: {
    sysinfoFile: { pattern: /^_?Information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^UserName \(ComputerName\)$/i, label: 'Sysinfo key: UserName (ComputerName)' },
      { pattern: /^Local Date and Time$/i, label: 'Sysinfo key: Local Date and Time' },
      { pattern: /^OS$/i, label: 'Sysinfo key: OS' },
      { pattern: /^Display Resolution$/i, label: 'Sysinfo key: Display Resolution' },
      { pattern: /^GPU$/i, label: 'Sysinfo key: GPU' },
      { pattern: /^RAM$/i, label: 'Sysinfo key: RAM' },
      { pattern: /^isGodMod$/i, label: 'Sysinfo key: isGodMod' },
      { pattern: /^isAdmin$/i, label: 'Sysinfo key: isAdmin' },
      { pattern: /^UserAgent$/i, label: 'Sysinfo key: UserAgent' },
      { pattern: /^Keyboard Languages$/i, label: 'Sysinfo key: Keyboard Languages' },
    ],
    sysinfoContent: [],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
      { pattern: /^Screenshot\.png$/i, label: 'File: Screenshot.png' },
    ],
    structures: [
      {
        test: (dirs, files) => {
          return files.some(f => /^_Information\.txt$/i.test(f));
        },
        label: 'Structure: _Information.txt (underscore prefix)',
      },
    ],
    require: ({ ctx }) => {
      if (/^UserName \(ComputerName\):/mi.test(ctx.sysinfoText || '')) return true;
      return (ctx.sysinfoKeys || []).some(k => /^(UserName \(ComputerName\)|isGodMod|isAdmin|UserAgent|Keyboard Languages)$/i.test(k));
    },
  },

  Phemedrone: {
    sysinfoFile: { pattern: /^Information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Hardware ID$/i, label: 'Sysinfo key: Hardware ID' },
      { pattern: /^File Location$/i, label: 'Sysinfo key: File Location' },
      { pattern: /^MAC$/i, label: 'Sysinfo key: MAC' },
      { pattern: /^Clipboard text$/i, label: 'Sysinfo key: Clipboard text' },
      { pattern: /^Antivirus products$/i, label: 'Sysinfo key: Antivirus products' },
    ],
    sysinfoContent: [
      { pattern: /^-----\s*Geolocation Data\s*-----$/m, label: 'Sysinfo section: ----- Geolocation Data -----' },
      { pattern: /^-----\s*Hardware Info\s*-----$/m, label: 'Sysinfo section: ----- Hardware Info -----' },
      { pattern: /^-----\s*Report Contents\s*-----$/m, label: 'Sysinfo section: ----- Report Contents -----' },
      { pattern: /^-----\s*Miscellaneous\s*-----$/m, label: 'Sysinfo section: ----- Miscellaneous -----' },
      { pattern: /^Passwords:\s*\d+$/mi, label: 'Sysinfo content: Password count' },
      { pattern: /^Cookies:\s*\d+$/mi, label: 'Sysinfo content: Cookie count' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
    require: ({ ctx, matchedCounts }) => {
      if (matchedCounts.sysinfoContent > 0) return true;
      return (ctx.sysinfoKeys || []).some(k => /^(Hardware ID|File Location|MAC)$/i.test(k));
    },
  },

  'DarkCrystal RAT': {
    selfId: [
      { pattern: /darkcrystal/i, label: 'Self-ID: DarkCrystal' },
      { pattern: /\bDCRAT\b/i, label: 'Self-ID: DCRAT', scope: 'sysinfo' },
    ],
    sysinfoFile: { pattern: /^Information(?:\s*\[[^\]]+\])?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^PC Name$/i, label: 'Sysinfo key: PC Name' },
      { pattern: /^User Name$/i, label: 'Sysinfo key: User Name' },
      { pattern: /^Monitors$/i, label: 'Sysinfo key: Monitors' },
      { pattern: /^Save Time$/i, label: 'Sysinfo key: Save Time' },
      { pattern: /^LANIP$/i, label: 'Sysinfo key: LANIP' },
      { pattern: /^\.NET Framework Version$/i, label: 'Sysinfo key: .NET Framework Version' },
    ],
    sysinfoContent: [
      { pattern: /DarkCrystal/i, label: 'Sysinfo content: DarkCrystal branding' },
      { pattern: /DCRAT/i, label: 'Sysinfo content: DCRAT branding' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
  },

  Meduza: {
    selfId: [
      { pattern: /meduza\s+stealer/i, label: 'Self-ID: Meduza stealer' },
      { pattern: /(?:⚡️?\s*)?NEW\s*LOG\s*\(NOT\s*ENCRYPTED\)/i, label: 'Self-ID: Meduza NEW LOG banner' },
    ],
    sysinfoFile: { pattern: /^(?:UserInfo|Information|PC_info)\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^Log Date$/i, label: 'Sysinfo key: Log Date' },
      { pattern: /^Build Name$/i, label: 'Sysinfo key: Build Name' },
      { pattern: /^User Name$/i, label: 'Sysinfo key: User Name' },
      { pattern: /^Computer Name$/i, label: 'Sysinfo key: Computer Name' },
      { pattern: /^Operation System$/i, label: 'Sysinfo key: Operation System' },
      { pattern: /^Time Zone$/i, label: 'Sysinfo key: Time Zone' },
      { pattern: /^Screen Resolution$/i, label: 'Sysinfo key: Screen Resolution' },
      { pattern: /^CPU$/i, label: 'Sysinfo key: CPU' },
      { pattern: /^GPU$/i, label: 'Sysinfo key: GPU' },
      { pattern: /^RAM$/i, label: 'Sysinfo key: RAM' },
      { pattern: /^IP$/i, label: 'Sysinfo key: IP' },
      { pattern: /^Execute Path$/i, label: 'Sysinfo key: Execute Path' },
      { pattern: /^Country Code$/i, label: 'Sysinfo key: Country Code' },
    ],
    sysinfoContent: [
      { pattern: /Meduza/i, label: 'Sysinfo content: Meduza branding' },
      { pattern: /^HWID:\s*[0-9a-f]{40}$/mi, label: 'Sysinfo content: 40-char hex HWID' },
      { pattern: /^Log Date:\s*\d{2}-\d{2}-\d{4},\s*\d{2}:\d{2}:\d{2}$/mi, label: 'Sysinfo content: DD-MM-YYYY, HH:MM:SS date format' },
      { pattern: /^(?:🔗\uFE0F?)?\s*Download link\s*:/m, label: 'Sysinfo content: 🔗 Download link section' },
      { pattern: /^🖥\uFE0F?\s*(?:General information|Computer info)/m, label: 'Sysinfo content: 🖥 Computer info section' },
      { pattern: /^📡\uFE0F?\s*Whois/m, label: 'Sysinfo content: 📡 Whois section' },
    ],
    folders: [
      { pattern: /^Browser$/i, label: 'Folder: Browser/' },
    ],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
  },

  Banshee: {
    osClass: 'macos',
    selfId: [
      { pattern: /banshee\s+stealer/i, label: 'Self-ID: Banshee stealer' },
    ],
    sysinfoFile: { pattern: /^system_information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^Log Date$/i, label: 'Sysinfo key: Log Date' },
      { pattern: /^Build Name$/i, label: 'Sysinfo key: Build Name' },
      { pattern: /^Country Code$/i, label: 'Sysinfo key: Country Code' },
      { pattern: /^User Name$/i, label: 'Sysinfo key: User Name' },
    ],
    sysinfoContent: [
      { pattern: /\bmacOS\b/i, label: 'Sysinfo content: macOS reference' },
      { pattern: /\b(?:MacBook|Apple Silicon|Apple M)\b/i, label: 'Sysinfo content: macOS hardware reference' },
    ],
    folders: [
      { pattern: /^Browsers$/i, label: 'Folder: Browsers/' },
    ],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
    require: ({ matchedCounts }) => matchedCounts.sysinfoContent > 0,
  },

  ExelaStealer: {
    selfId: [
      { pattern: /exelastealer/i, label: 'Self-ID: ExelaStealer' },
    ],
    sysinfoFile: { pattern: /^System(?:[\s_]*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [],
    sysinfoContent: [
      { pattern: /^####\s*System Info\s*####$/m, label: 'Sysinfo section: ####System Info####' },
      { pattern: /^####\s*Host Name\s*####$/m, label: 'Sysinfo section: ####Host Name####' },
      { pattern: /^####\s*Logical Disk\s*####$/m, label: 'Sysinfo section: ####Logical Disk####' },
      { pattern: /-{10,}https:\/\/t\.me\/ExelaStealer-{10,}/i, label: 'Sysinfo content: ExelaStealer Telegram banner' },
      { pattern: /t\.me\/exelastealer/i, label: 'Sysinfo content: Telegram Exela URL' },
      { pattern: /ExelaStealer/i, label: 'Sysinfo content: ExelaStealer branding' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
    require: ({ matchedCounts }) => matchedCounts.sysinfoContent > 0 || matchedCounts.selfId > 0,
  },

  Stealerium: {
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^External IP$/i, label: 'Sysinfo key: External IP' },
      { pattern: /^Internal IP$/i, label: 'Sysinfo key: Internal IP' },
      { pattern: /^Gateway IP$/i, label: 'Sysinfo key: Gateway IP' },
      { pattern: /^VirtualMachine$/i, label: 'Sysinfo key: VirtualMachine' },
      { pattern: /^SandBoxie$/i, label: 'Sysinfo key: SandBoxie' },
      { pattern: /^Emulator$/i, label: 'Sysinfo key: Emulator' },
      { pattern: /^Hosting$/i, label: 'Sysinfo key: Hosting' },
      { pattern: /^BATTERY$/i, label: 'Sysinfo key: BATTERY' },
      { pattern: /^WEBCAMS COUNT$/i, label: 'Sysinfo key: WEBCAMS COUNT' },
    ],
    sysinfoContent: [
      { pattern: /^\*?(?:Stealerium|Phantom stealer)\s*-\s*Report:/mi, label: 'Sysinfo content: report header' },
      { pattern: /\[IP\]/i, label: 'Sysinfo section: [IP]' },
      { pattern: /\[Machine\]/i, label: 'Sysinfo section: [Machine]' },
      { pattern: /\[Virtualization\]/i, label: 'Sysinfo section: [Virtualization]' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
    require: ({ matchedCounts }) => matchedCounts.sysinfoContent > 0 || matchedCounts.sysinfoKey >= 2,
  },

  XFiles: {
    selfId: [
      { pattern: /xfiles/i, label: 'Self-ID: XFiles', scope: 'sysinfo' },
      { pattern: /luciferxfiles/i, label: 'Self-ID: luciferxfiles' },
    ],
    sysinfoFile: { pattern: /^(?:System(?:\s*)?)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Operation ID$/i, label: 'Sysinfo key: Operation ID' },
      { pattern: /^Operating System$/i, label: 'Sysinfo key: Operating System' },
      { pattern: /^Screens$/i, label: 'Sysinfo key: Screens' },
    ],
    sysinfoContent: [
      { pattern: /Desktop Screenshot Taken/i, label: 'Sysinfo content: Desktop Screenshot Taken' },
      { pattern: /Windows Processes/i, label: 'Sysinfo content: Windows Processes section' },
    ],
    folders: [
      { pattern: /^Browsers$/i, label: 'Folder: Browsers/' },
      { pattern: /^Email\s*Clients$/i, label: 'Folder: Email Clients/' },
    ],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
      { pattern: /^All\s*Passwords\.txt$/i, label: 'File: All Passwords.txt' },
      { pattern: /^Desktop\s*Screenshot\b/i, label: 'File: Desktop Screenshot' },
      { pattern: /^User-Agents/i, label: 'File: User-Agents' },
      { pattern: /^Installed\s*Software\s*\[\d+\]\.txt$/i, label: 'File: Installed Software [N].txt' },
    ],
    structures: [
      {
        test: (dirs, files) => {
          const hasBrowsers = dirs.some(d => /^Browsers$/i.test(d));
          const hasScreenshot = files.some(f => /Desktop\s*Screenshot/i.test(f));
          return hasBrowsers && hasScreenshot;
        },
        label: 'Structure: Browsers/ + Desktop Screenshot',
      },
    ],
  },

  Noxty: {
    sysinfoFile: { pattern: /^identification\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^User$/i, label: 'Sysinfo key: User' },
      { pattern: /^Operating System$/i, label: 'Sysinfo key: Operating System' },
      { pattern: /^Process Executable Path$/i, label: 'Sysinfo key: Process Executable Path' },
      { pattern: /^Uptime$/i, label: 'Sysinfo key: Uptime' },
      { pattern: /^ScreenResolution$/i, label: 'Sysinfo key: ScreenResolution' },
      { pattern: /^Disk Devices$/i, label: 'Sysinfo key: Disk Devices' },
    ],
    sysinfoContent: [],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
  },

  Skalka: {
    selfId: [
      { pattern: /skalka/i, label: 'Self-ID: Skalka', scope: 'sysinfo' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Operation System$/i, label: 'Sysinfo key: Operation System' },
      { pattern: /^Current JarFile Path$/i, label: 'Sysinfo key: Current JarFile Path (Java-based)' },
      { pattern: /^Width$/i, label: 'Sysinfo key: Width' },
      { pattern: /^UserName$/i, label: 'Sysinfo key: UserName' },
      { pattern: /^Language & Country$/i, label: 'Sysinfo key: Language & Country' },
    ],
    sysinfoContent: [
      { pattern: /Skalka/i, label: 'Sysinfo content: Skalka branding' },
    ],
    folders: [],
    files: [],
    structures: [],
  },

  RLStealer: {
    selfId: [
      { pattern: /rl\s*stealer/i, label: 'Self-ID: RL Stealer' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Operating system\s*$/i, label: 'Sysinfo key: Operating system (trailing space)' },
      { pattern: /^PC user\s*$/i, label: 'Sysinfo key: PC user (trailing space)' },
      { pattern: /^ClipBoard\s*$/i, label: 'Sysinfo key: ClipBoard' },
      { pattern: /^Current time\s*$/i, label: 'Sysinfo key: Current time' },
      { pattern: /^HWID\s*$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^BSSID\s*$/i, label: 'Sysinfo key: BSSID' },
    ],
    sysinfoContent: [
      { pattern: /RL\s*Stealer/i, label: 'Sysinfo content: RL Stealer branding' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
    ],
    structures: [],
  },

  Ailurophile: {
    selfId: [
      { pattern: /ailurophile/i, label: 'Self-ID: Ailurophile', scope: 'sysinfo' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^PC Type$/i, label: 'Sysinfo key: PC Type' },
      { pattern: /^Allowed Extensions$/i, label: 'Sysinfo key: Allowed Extensions' },
    ],
    sysinfoContent: [
      { pattern: /PC Type:\s*Microsoft Windows/i, label: 'Sysinfo content: PC Type Microsoft Windows' },
      { pattern: /Ailurophile/i, label: 'Sysinfo content: Ailurophile branding' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
  },

  ArechClientV2: {
    selfId: [
      { pattern: /arechclient/i, label: 'Self-ID: ArechClient' },
    ],
    sysinfoFile: { pattern: /^UserInformation\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [],
    sysinfoContent: [
      { pattern: /ArechClient/i, label: 'Sysinfo content: ArechClient branding' },
      { pattern: /ScreenSize:\s*\{Width\s*=\s*[^}]+\}TimeZone:/i, label: 'Sysinfo content: ScreenSize/TimeZone formatting quirk' },
      { pattern: /^Process Elevation:\s*(?:True|False)$/mi, label: 'Sysinfo content: Process Elevation boolean' },
      { pattern: /^Available KeyboardLayouts:/mi, label: 'Sysinfo content: Available KeyboardLayouts section' },
      { pattern: /^Anti-Viruses:/mi, label: 'Sysinfo content: Anti-Viruses section' },
    ],
    folders: [],
    files: [],
    structures: [],
    require: ({ matchedCounts }) => matchedCounts.selfId > 0 || matchedCounts.sysinfoContent > 0,
  },

  PXA: {
    sysinfoFile: { pattern: /^UserInformation\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Build ID$/i, label: 'Sysinfo key: Build ID' },
      { pattern: /^Build Comment$/i, label: 'Sysinfo key: Build Comment' },
      { pattern: /^Build Version$/i, label: 'Sysinfo key: Build Version' },
      { pattern: /^Active window$/i, label: 'Sysinfo key: Active window' },
      { pattern: /^User time$/i, label: 'Sysinfo key: User time' },
      { pattern: /^GEO$/i, label: 'Sysinfo key: GEO' },
    ],
    sysinfoContent: [
      { pattern: /^Build Comment:/mi, label: 'Sysinfo content: Build Comment line' },
      { pattern: /^Active window:/mi, label: 'Sysinfo content: Active window line' },
      { pattern: /^GEO:\s*\S/mi, label: 'Sysinfo content: GEO line' },
    ],
    folders: [
      { pattern: /^\[Simple Checker\]$/i, label: 'Folder: [Simple Checker]/' },
      { pattern: /^Clients$/i, label: 'Folder: Clients/' },
      { pattern: /^Browsers$/i, label: 'Folder: Browsers/' },
    ],
    files: [
      // Browsers/ is the usual home, but a minimal log ships the trio at the root.
      { pattern: /^(?:Browsers\/)?Logins_[A-Za-z]+_[^./]+\.txt$/i, label: 'File: Logins_{Browser}_{Profile}.txt' },
      { pattern: /^(?:Browsers\/)?Autofills_[A-Za-z]+_[^./]+\.txt$/i, label: 'File: Autofills_{Browser}_{Profile}.txt' },
      { pattern: /^(?:Browsers\/)?Cookies_[A-Za-z]+_[^./]+\.txt$/i, label: 'File: Cookies_{Browser}_{Profile}.txt' },
      { pattern: /^(?:Browsers\/)?Token_[A-Za-z]+_[^./]+\.txt$/i, label: 'File: Token_{Browser}_{Profile}.txt' },
      { pattern: /^Clients\/DiscordTokens\.txt$/i, label: 'File: Clients/DiscordTokens.txt' },
    ],
    structures: [
      {
        test: (dirs, files) => {
          const hasToken = files.some(f => /^Browsers\/Token_[^/]+_[^/]+\.txt$/i.test(f));
          const hasChecker = dirs.some(d => /^\[Simple Checker\]/i.test(d)) ||
            files.some(f => /^\[Simple Checker\]\//i.test(f));
          return hasToken && hasChecker;
        },
        label: 'Structure: Browsers/Token_* with [Simple Checker]/',
      },
    ],
    require: ({ matchedCounts }) =>
      matchedCounts.sysinfoKey >= 2 || matchedCounts.structure > 0 ||
      matchedCounts.folder >= 2 || matchedCounts.file >= 2,
  },

  BlankGrabber: {
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [],
    sysinfoContent: [
      { pattern: /Blank\s*Grabber/i, label: 'Sysinfo content: Blank Grabber branding' },
    ],
    folders: [],
    files: [
      { pattern: /^Task\s*List\.txt$/i, label: 'File: Task List.txt' },
      { pattern: /^Display(?: \(\d+\))?\.png$/i, label: 'File: Display (N).png' },
    ],
    structures: [
      {
        test: (dirs, files) => {
          const hasSysinfo = files.some(f => /^System(?:\s*)?Info(?:rmation)?\.txt$/i.test(f));
          const hasTaskList = files.some(f => /^Task\s*List\.txt$/i.test(f));
          const hasDisplayShot = files.some(f => /^Display(?: \(\d+\))?\.png$/i.test(f));
          return hasSysinfo && (hasTaskList || hasDisplayShot);
        },
        label: 'Structure: systeminfo output plus task list or display screenshot',
      },
    ],
    require: ({ matchedCounts }) => matchedCounts.file > 0 || matchedCounts.structure > 0,
  },

  'PredatorTheThief v3': {
    sysinfoFile: { pattern: /^Information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Launch time$/i, label: 'Sysinfo key: Launch time' },
      { pattern: /^Startup folder$/i, label: 'Sysinfo key: Startup folder' },
      { pattern: /^Amount of kernels$/i, label: 'Sysinfo key: Amount of kernels' },
      { pattern: /^GPU info$/i, label: 'Sysinfo key: GPU info' },
      { pattern: /^Amount of RAM$/i, label: 'Sysinfo key: Amount of RAM' },
    ],
    sysinfoContent: [
      { pattern: /Predator The Thief\s*:\s*v3/i, label: 'Sysinfo content: PredatorTheThief v3 header' },
      { pattern: /Predator\s*The\s*Thief/i, label: 'Sysinfo content: Predator The Thief branding' },
      { pattern: /PredatorTheThief/i, label: 'Sysinfo content: PredatorTheThief branding' },
    ],
    folders: [],
    files: [
      { pattern: /^passwords\.txt$/i, label: 'File: passwords.txt' },
      { pattern: /^cookies\.txt$/i, label: 'File: cookies.txt' },
    ],
    structures: [],
  },

  LucaStealer: {
    sysinfoFile: { pattern: /^user_info\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Antivirus$/i, label: 'Sysinfo key: Antivirus' },
      { pattern: /^FileLocation$/i, label: 'Sysinfo key: FileLocation' },
      { pattern: /^Is Elevated$/i, label: 'Sysinfo key: Is Elevated' },
    ],
    sysinfoContent: [
      { pattern: /^-\s*IP Info\s*-$/m, label: 'Sysinfo section: - IP Info -' },
      { pattern: /^-\s*PC Info\s*-$/m, label: 'Sysinfo section: - PC Info -' },
      { pattern: /^-\s*Other Info\s*-$/m, label: 'Sysinfo section: - Other Info -' },
      { pattern: /^-\s*Log Info\s*-$/m, label: 'Sysinfo section: - Log Info -' },
      { pattern: /Luca\s*Stealer/i, label: 'Sysinfo content: Luca Stealer branding' },
      { pattern: /LucaStealer/i, label: 'Sysinfo content: LucaStealer branding' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
    ],
    structures: [],
  },

};

