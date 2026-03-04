// Stealer signatures, detection patterns, session cookie names, field maps, etc.
// New stealer family? Add to SIGNATURES. New file type? FILE_TYPE_PATTERNS + detection.js + analysis.js.
// New session cookie? AUTH_COOKIE_NAMES or SESSION_PATTERNS. New IOC? IOC_KEY_MAP.


// Stealer signatures

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

export const SIGNATURES = {
  Vidar: {
    selfId: [
      { pattern: /vidar\s+stealer/i, label: 'Self-ID: Vidar stealer' },
    ],
    sysinfoFile: { pattern: /^information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Version$/i, label: 'Sysinfo key: Version' },
      { pattern: /^GUID$/i, label: 'Sysinfo key: GUID' },
      { pattern: /^Work Dir$/i, label: 'Sysinfo key: Work Dir' },
      { pattern: /^MachineID$/i, label: 'Sysinfo key: MachineID' },
    ],
    sysinfoContent: [
      { pattern: /VIDAR/i, label: 'Sysinfo header: VIDAR branding' },
      { pattern: /vidars\.su/i, label: 'Sysinfo content: vidars.su URL' },
      { pattern: /[\u0400-\u04FF]{3,}/u, label: 'Sysinfo content: Cyrillic text' },
    ],
    folders: [
      { pattern: /^Autofill$/i, label: 'Folder: Autofill/' },
      { pattern: /^Cookies$/i, label: 'Folder: Cookies/' },
      { pattern: /^History$/i, label: 'Folder: History/' },
    ],
    files: [
      { pattern: /^unique_passwords\.txt$/i, label: 'File: unique_passwords.txt' },
      { pattern: /^domain detect\.txt$/i, label: 'File: domain detect.txt' },
      { pattern: /^screenshot\.jpg$/i, label: 'File: screenshot.jpg' },
      { pattern: /^passwords\.txt$/i, label: 'File: passwords.txt (root)' },
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
  },

  RedLine: {
    selfId: [
      { pattern: /redline\s+stealer/i, label: 'Self-ID: RedLine stealer' },
    ],
    sysinfoFile: { pattern: /^UserInformation\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Domain Name$/i, label: 'Sysinfo key: Domain Name' },
      { pattern: /^Admin Group$/i, label: 'Sysinfo key: Admin Group' },
      { pattern: /^Integrity$/i, label: 'Sysinfo key: Integrity' },
      { pattern: /^Display Resolution$/i, label: 'Sysinfo key: Display Resolution' },
    ],
    sysinfoContent: [
      { pattern: /REDLINE/i, label: 'Sysinfo header: REDLINE branding' },
      { pattern: /@logs_russia/i, label: 'Sysinfo content: @logs_russia' },
    ],
    asciiBanners: [
      '* ____ _____ ____ _ ___ _ _ _____ *',
      '* | _ \\|_____| _ \\',
    ],
    folders: [
      { pattern: /^Browser$/i, label: 'Folder: Browser/' },
      { pattern: /^Browser\/AutoFills$/i, label: 'Folder: Browser/AutoFills/' },
      { pattern: /^Browser\/Passwords$/i, label: 'Folder: Browser/Passwords/' },
      { pattern: /^Browser\/GoogleAccounts$/i, label: 'Folder: Browser/GoogleAccounts/' },
      { pattern: /^Games$/i, label: 'Folder: Games/' },
      { pattern: /^Mails$/i, label: 'Folder: Mails/' },
    ],
    files: [
      { pattern: /^Clipboard\.txt$/i, label: 'File: Clipboard.txt' },
      { pattern: /^ProcessList\.txt$/i, label: 'File: ProcessList.txt' },
      { pattern: /^InstalledSoftware\.txt$/i, label: 'File: InstalledSoftware.txt' },
      { pattern: /^DungeonChecker/i, label: 'File: DungeonChecker*.txt' },
    ],
    structures: [
      {
        test: (dirs) => {
          const hasBrowser = dirs.some(d => /^Browser$/i.test(d));
          const hasBrowserPasswords = dirs.some(d => /^Browser\/Passwords$/i.test(d));
          const noFingerPrint = !dirs.some(d => /^Browser\/FingerPrint$/i.test(d));
          const noMasterKeys = !dirs.some(d => /^Browser\/MasterKeys$/i.test(d));
          return hasBrowser && hasBrowserPasswords && noFingerPrint && noMasterKeys;
        },
        label: 'Structure: Browser/ without FingerPrint/MasterKeys',
      },
    ],
  },

  Rhadamanthys: {
    selfId: [
      { pattern: /rhadamanthys/i, label: 'Self-ID: Rhadamanthys' },
    ],
    sysinfoFile: { pattern: /^UserInformation\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
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
  },

  Lumma: {
    selfId: [
      { pattern: /lummac2/i, label: 'Self-ID: LummaC2' },
      { pattern: /lumma\s+stealer/i, label: 'Self-ID: Lumma stealer' },
    ],
    sysinfoFile: { pattern: /^UserInformation\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Traffic$/i, label: 'Sysinfo key: Traffic' },
      { pattern: /^Version Build$/i, label: 'Sysinfo key: Version Build' },
      { pattern: /^Log date$/i, label: 'Sysinfo key: Log date' },
    ],
    sysinfoContent: [
      { pattern: /LummaC2/i, label: 'Sysinfo content: LummaC2 branding' },
      { pattern: /\bLID:\s*/i, label: 'Sysinfo content: LID field' },
      { pattern: /Configuration:\s*/i, label: 'Sysinfo content: Configuration field' },
    ],
    folders: [
      { pattern: /^Browser$/i, label: 'Folder: Browser/' },
      { pattern: /^Browser\/AutoFills$/i, label: 'Folder: Browser/AutoFills/' },
      { pattern: /^Browser\/CreditCards$/i, label: 'Folder: Browser/CreditCards/' },
      { pattern: /^Messengers$/i, label: 'Folder: Messengers/' },
      { pattern: /^Messengers\/Discord$/i, label: 'Folder: Messengers/Discord/' },
    ],
    files: [
      { pattern: /^CreditCards\.txt$/i, label: 'File: CreditCards.txt (root)' },
      { pattern: /^Clipboard\.txt$/i, label: 'File: Clipboard.txt' },
    ],
    structures: [
      {
        test: (dirs, files) => {
          return files.some(f => /Cookies\/[^/]+_\[[a-z0-9]{5}\]\.txt$/i.test(f));
        },
        label: 'Structure: cookie files with _[5char] hash suffix',
      },
      {
        test: (dirs, files) => {
          const hasBrowser = dirs.some(d => /^Browser$/i.test(d));
          const hasMessengers = dirs.some(d => /^Messengers$/i.test(d));
          const noFingerPrint = !dirs.some(d => /^Browser\/FingerPrint$/i.test(d));
          return hasBrowser && hasMessengers && noFingerPrint;
        },
        label: 'Structure: Browser/ + Messengers/ without FingerPrint',
      },
    ],
  },

  Stealc: {
    selfId: [
      { pattern: /stealc\s+stealer/i, label: 'Self-ID: Stealc stealer' },
      { pattern: /STEALC/i, label: 'Self-ID: STEALC branding' },
    ],
    sysinfoFile: { pattern: /^(?:Info|system_info)\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Build Date$/i, label: 'Sysinfo key: Build Date' },
      { pattern: /^Elevated$/i, label: 'Sysinfo key: Elevated' },
      { pattern: /^Netbios$/i, label: 'Sysinfo key: Netbios' },
      { pattern: /^Execution Path$/i, label: 'Sysinfo key: Execution Path' },
      { pattern: /^Running Path$/i, label: 'Sysinfo key: Running Path' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^Laptop$/i, label: 'Sysinfo key: Laptop' },
    ],
    sysinfoContent: [
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

  Cuckoo: {
    selfId: [
      { pattern: /cuckoo\s+stealer/i, label: 'Self-ID: Cuckoo stealer' },
    ],
    sysinfoFile: { pattern: /^system_info\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Laptop$/i, label: 'Sysinfo key: Laptop' },
      { pattern: /^Running Path$/i, label: 'Sysinfo key: Running Path' },
    ],
    sysinfoContent: [
      { pattern: /^Network Info:/m, label: 'Sysinfo section: Network Info' },
      { pattern: /^System Summary:/m, label: 'Sysinfo section: System Summary' },
    ],
    folders: [
      { pattern: /^browsers$/i, label: 'Folder: browsers/ (raw SQLite)' },
      { pattern: /^keys$/i, label: 'Folder: keys/' },
      { pattern: /^AccountTokens$/i, label: 'Folder: AccountTokens/' },
      { pattern: /^cookies$/i, label: 'Folder: cookies/ (lowercase)' },
      { pattern: /^autofill$/i, label: 'Folder: autofill/ (lowercase)' },
    ],
    files: [
      { pattern: /^cookie_list\.txt$/i, label: 'File: cookie_list.txt' },
    ],
    structures: [
      {
        test: (dirs, files) => {
          return files.some(f => /^keys\/[^/]+\/v10\.txt$/i.test(f));
        },
        label: 'Structure: keys/{browser}/v10.txt',
      },
      {
        test: (dirs) => {
          return dirs.some(d => /^browsers\/[^/]+\/[^/]+$/i.test(d));
        },
        label: 'Structure: browsers/{browser}/{profile}/ (raw DBs)',
      },
      {
        test: (dirs) => {
          // Cuckoo-specific: requires both browsers/ and keys/ dirs (distinguishes from Stealc v2)
          const hasBrowsers = dirs.some(d => /^browsers$/i.test(d));
          const hasKeys = dirs.some(d => /^keys$/i.test(d));
          return hasBrowsers && hasKeys;
        },
        label: 'Structure: browsers/ + keys/ (Cuckoo-specific raw DB layout)',
      },
    ],
  },

  MacSync: {
    selfId: [
      { pattern: /macsync\s+stealer/i, label: 'Self-ID: MacSync Stealer' },
    ],
    sysinfoFile: { pattern: /^Information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Build Tag$/i, label: 'Sysinfo key: Build Tag' },
    ],
    sysinfoContent: [
      { pattern: /MacSync Stealer/i, label: 'Sysinfo header: MacSync Stealer' },
      { pattern: /x64_86 & ARM/i, label: 'Sysinfo content: x64_86 & ARM version' },
    ],
    folders: [
      { pattern: /^Autofills$/i, label: 'Folder: Autofills/' },
      { pattern: /^Cookies$/i, label: 'Folder: Cookies/' },
    ],
    files: [
      { pattern: /^iCloud Passwords\.txt$/i, label: 'File: iCloud Passwords.txt' },
      { pattern: /^Keychain Data\.txt$/i, label: 'File: Keychain Data.txt' },
      { pattern: /^BruteList\.txt$/i, label: 'File: BruteList.txt' },
      { pattern: /^GoogleTokens_[^/]+\.txt$/i, label: 'File: GoogleTokens_{Profile}.txt' },
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

  MarsStaler: {
    selfId: [
      { pattern: /mars\s+stealer/i, label: 'Self-ID: Mars Stealer' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Computer\s*Name$/i, label: 'Sysinfo key: Computer Name' },
      { pattern: /^User\s*Name$/i, label: 'Sysinfo key: User Name' },
      { pattern: /^IP$/i, label: 'Sysinfo key: IP' },
      { pattern: /^Tracker$/i, label: 'Sysinfo key: Tracker' },
      { pattern: /^Build\s*ID$/i, label: 'Sysinfo key: Build ID' },
    ],
    sysinfoContent: [
      { pattern: /Mars\s*Stealer/i, label: 'Sysinfo content: Mars Stealer branding' },
    ],
    folders: [
      { pattern: /^Browser$/i, label: 'Folder: Browser/' },
      { pattern: /^Browser\/Passwords$/i, label: 'Folder: Browser/Passwords/' },
      { pattern: /^Wallets$/i, label: 'Folder: Wallets/' },
    ],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Screenshot\.jpg$/i, label: 'File: Screenshot.jpg' },
      { pattern: /^Grabber$/i, label: 'File: Grabber data' },
    ],
    structures: [
      {
        test: (dirs) => {
          const hasBrowser = dirs.some(d => /^Browser$/i.test(d));
          const hasWallets = dirs.some(d => /^Wallets$/i.test(d));
          return hasBrowser && hasWallets;
        },
        label: 'Structure: Browser/ + Wallets/ present',
      },
    ],
  },

  RisePro: {
    selfId: [
      { pattern: /risepro/i, label: 'Self-ID: RisePro' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Build$/i, label: 'Sysinfo key: Build' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^IP$/i, label: 'Sysinfo key: IP' },
    ],
    sysinfoContent: [
      { pattern: /RisePro/i, label: 'Sysinfo content: RisePro branding' },
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
  },

  MysticStealer: {
    selfId: [
      { pattern: /mystic\s*stealer/i, label: 'Self-ID: Mystic Stealer' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Bot\s*ID$/i, label: 'Sysinfo key: Bot ID' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^Computer\s*Name$/i, label: 'Sysinfo key: Computer Name' },
    ],
    sysinfoContent: [
      { pattern: /Mystic\s*Stealer/i, label: 'Sysinfo content: Mystic Stealer branding' },
    ],
    folders: [
      { pattern: /^Browsers$/i, label: 'Folder: Browsers/' },
      { pattern: /^Files$/i, label: 'Folder: Files/' },
    ],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
      { pattern: /^AutoFill\.txt$/i, label: 'File: AutoFill.txt' },
      { pattern: /^CreditCards\.txt$/i, label: 'File: CreditCards.txt' },
    ],
    structures: [],
  },

  AuroraStealer: {
    selfId: [
      { pattern: /aurora\s*stealer/i, label: 'Self-ID: Aurora Stealer' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Build$/i, label: 'Sysinfo key: Build' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^IP$/i, label: 'Sysinfo key: IP' },
    ],
    sysinfoContent: [
      { pattern: /Aurora\s*Stealer/i, label: 'Sysinfo content: Aurora Stealer branding' },
    ],
    folders: [
      { pattern: /^Browsers$/i, label: 'Folder: Browsers/' },
      { pattern: /^Crypto$/i, label: 'Folder: Crypto/' },
      { pattern: /^Plugins$/i, label: 'Folder: Plugins/' },
    ],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
      { pattern: /^Screen\.png$/i, label: 'File: Screen.png' },
    ],
    structures: [
      {
        test: (dirs) => {
          const hasBrowsers = dirs.some(d => /^Browsers$/i.test(d));
          const hasCrypto = dirs.some(d => /^Crypto$/i.test(d));
          return hasBrowsers && hasCrypto;
        },
        label: 'Structure: Browsers/ + Crypto/ present',
      },
    ],
  },

  AtomicStealer: {
    selfId: [
      { pattern: /atomic\s*stealer/i, label: 'Self-ID: Atomic Stealer' },
      { pattern: /\bamos\b/i, label: 'Self-ID: AMOS (Atomic macOS Stealer)' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Mac\s*OS\s*Version$/i, label: 'Sysinfo key: MacOS Version' },
      { pattern: /^Hardware\s*UUID$/i, label: 'Sysinfo key: Hardware UUID' },
    ],
    sysinfoContent: [
      { pattern: /Atomic/i, label: 'Sysinfo content: Atomic branding' },
      { pattern: /macOS|darwin/i, label: 'Sysinfo content: macOS reference' },
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
  },

  WhiteSnake: {
    selfId: [
      { pattern: /whitesnake/i, label: 'Self-ID: WhiteSnake' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Build\s*ID$/i, label: 'Sysinfo key: Build ID' },
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^Tag$/i, label: 'Sysinfo key: Tag' },
    ],
    sysinfoContent: [
      { pattern: /WhiteSnake/i, label: 'Sysinfo content: WhiteSnake branding' },
    ],
    folders: [
      { pattern: /^Browsers$/i, label: 'Folder: Browsers/' },
      { pattern: /^Files$/i, label: 'Folder: Files/' },
      { pattern: /^Wallets$/i, label: 'Folder: Wallets/' },
      { pattern: /^Messengers$/i, label: 'Folder: Messengers/' },
    ],
    files: [
      { pattern: /^Screenshot\.png$/i, label: 'File: Screenshot.png' },
      { pattern: /^ProcessList\.txt$/i, label: 'File: ProcessList.txt' },
      { pattern: /^InstalledApps\.txt$/i, label: 'File: InstalledApps.txt' },
    ],
    structures: [
      {
        test: (dirs) => {
          const hasBrowsers = dirs.some(d => /^Browsers$/i.test(d));
          const hasWallets = dirs.some(d => /^Wallets$/i.test(d));
          const hasMessengers = dirs.some(d => /^Messengers$/i.test(d));
          return hasBrowsers && hasWallets && hasMessengers;
        },
        label: 'Structure: Browsers/ + Wallets/ + Messengers/',
      },
    ],
  },

  META: {
    selfId: [
      { pattern: /meta\s+stealer/i, label: 'Self-ID: META stealer' },
    ],
    sysinfoFile: { pattern: /^UserInformation\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Domain\s*Name$/i, label: 'Sysinfo key: Domain Name' },
      { pattern: /^Admin\s*Group$/i, label: 'Sysinfo key: Admin Group' },
      { pattern: /^Display\s*Resolution$/i, label: 'Sysinfo key: Display Resolution' },
      { pattern: /^Build\s*ID$/i, label: 'Sysinfo key: Build ID' },
    ],
    sysinfoContent: [
      { pattern: /\(\s*M\s*\|\s*E\s*\|\s*T\s*\|\s*A\s*\)/, label: 'Sysinfo content: META ASCII banner' },
    ],
    asciiBanners: [
      '( M | E | T | A )',
    ],
    folders: [
      { pattern: /^Browser$/i, label: 'Folder: Browser/' },
      { pattern: /^Browser\/Passwords$/i, label: 'Folder: Browser/Passwords/' },
      { pattern: /^Browser\/Cookies$/i, label: 'Folder: Browser/Cookies/' },
      { pattern: /^Wallets$/i, label: 'Folder: Wallets/' },
    ],
    files: [
      { pattern: /^Clipboard\.txt$/i, label: 'File: Clipboard.txt' },
      { pattern: /^ProcessList\.txt$/i, label: 'File: ProcessList.txt' },
      { pattern: /^InstalledSoftware\.txt$/i, label: 'File: InstalledSoftware.txt' },
    ],
    structures: [
      {
        test: (dirs) => {
          const hasBrowser = dirs.some(d => /^Browser$/i.test(d));
          const hasWallets = dirs.some(d => /^Wallets$/i.test(d));
          const noBrowserFingerPrint = !dirs.some(d => /^Browser\/FingerPrint$/i.test(d));
          return hasBrowser && hasWallets && noBrowserFingerPrint;
        },
        label: 'Structure: Browser/ + Wallets/ without FingerPrint (META variant)',
      },
    ],
  },

  CryptBot: {
    sysinfoFile: { pattern: /^_?Information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^UserName \(ComputerName\)$/i, label: 'Sysinfo key: UserName (ComputerName)' },
      { pattern: /^Local Date and Time$/i, label: 'Sysinfo key: Local Date and Time' },
      { pattern: /^Display Resolution$/i, label: 'Sysinfo key: Display Resolution' },
      { pattern: /^GPU$/i, label: 'Sysinfo key: GPU' },
      { pattern: /^RAM$/i, label: 'Sysinfo key: RAM' },
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
  },

  Phemedrone: {
    sysinfoFile: { pattern: /^Information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Clipboard text$/i, label: 'Sysinfo key: Clipboard text' },
      { pattern: /^Antivirus products$/i, label: 'Sysinfo key: Antivirus products' },
    ],
    sysinfoContent: [
      { pattern: /Geolocation Data/i, label: 'Sysinfo section: Geolocation Data' },
      { pattern: /Hardware Info/i, label: 'Sysinfo section: Hardware Info' },
      { pattern: /Report Contents/i, label: 'Sysinfo section: Report Contents' },
      { pattern: /Miscellaneous/i, label: 'Sysinfo section: Miscellaneous' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
  },

  DarkCrystalRAT: {
    selfId: [
      { pattern: /darkcrystal/i, label: 'Self-ID: DarkCrystal' },
      { pattern: /\bDCRAT\b/i, label: 'Self-ID: DCRAT' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^PC Name$/i, label: 'Sysinfo key: PC Name' },
      { pattern: /^User Name$/i, label: 'Sysinfo key: User Name' },
    ],
    sysinfoContent: [
      { pattern: /DarkCrystal/i, label: 'Sysinfo content: DarkCrystal branding' },
      { pattern: /DCRAT/i, label: 'Sysinfo content: DCRAT branding' },
    ],
    asciiBanners: [
      '___   _   ___   _   ______',
      'DarkCrystal',
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
    ],
    sysinfoFile: { pattern: /^UserInfo\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^HWID$/i, label: 'Sysinfo key: HWID' },
      { pattern: /^Log Date$/i, label: 'Sysinfo key: Log Date' },
      { pattern: /^Build Name$/i, label: 'Sysinfo key: Build Name' },
      { pattern: /^Computer Name$/i, label: 'Sysinfo key: Computer Name' },
      { pattern: /^Operation System$/i, label: 'Sysinfo key: Operation System' },
      { pattern: /^Execute Path$/i, label: 'Sysinfo key: Execute Path' },
      { pattern: /^Country Code$/i, label: 'Sysinfo key: Country Code' },
    ],
    sysinfoContent: [
      { pattern: /Meduza/i, label: 'Sysinfo content: Meduza branding' },
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
      { pattern: /^Operation System$/i, label: 'Sysinfo key: Operation System (typo is signature)' },
    ],
    sysinfoContent: [
      { pattern: /macOS/i, label: 'Sysinfo content: macOS reference' },
    ],
    folders: [
      { pattern: /^Browsers$/i, label: 'Folder: Browsers/' },
    ],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
  },

  ExelaStealer: {
    selfId: [
      { pattern: /exelastealer/i, label: 'Self-ID: ExelaStealer' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Host Name$/i, label: 'Sysinfo key: Host Name' },
      { pattern: /^OS Name$/i, label: 'Sysinfo key: OS Name' },
      { pattern: /^OS Version$/i, label: 'Sysinfo key: OS Version' },
    ],
    sysinfoContent: [
      { pattern: /t\.me\/exelastealer/i, label: 'Sysinfo content: Telegram Exela URL' },
      { pattern: /ExelaStealer/i, label: 'Sysinfo content: ExelaStealer branding' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
  },

  Stealerium: {
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^VirtualMachine$/i, label: 'Sysinfo key: VirtualMachine' },
      { pattern: /^BATTERY$/i, label: 'Sysinfo key: BATTERY' },
      { pattern: /^WEBCAMS COUNT$/i, label: 'Sysinfo key: WEBCAMS COUNT' },
    ],
    sysinfoContent: [
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
  },

  XFiles: {
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Operation ID$/i, label: 'Sysinfo key: Operation ID' },
      { pattern: /^Operating System$/i, label: 'Sysinfo key: Operating System' },
      { pattern: /^Screens$/i, label: 'Sysinfo key: Screens' },
    ],
    sysinfoContent: [
      { pattern: /Desktop Screenshot Taken/i, label: 'Sysinfo content: Desktop Screenshot Taken' },
      { pattern: /Windows Processes/i, label: 'Sysinfo content: Windows Processes section' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
  },

  Noxty: {
    sysinfoFile: { pattern: /^identification\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^User$/i, label: 'Sysinfo key: User' },
      { pattern: /^Operating System$/i, label: 'Sysinfo key: Operating System' },
      { pattern: /^Uptime$/i, label: 'Sysinfo key: Uptime' },
      { pattern: /^ScreenResolution$/i, label: 'Sysinfo key: ScreenResolution' },
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
      { pattern: /skalka/i, label: 'Self-ID: Skalka' },
    ],
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Operation System$/i, label: 'Sysinfo key: Operation System' },
      { pattern: /^Current JarFile Path$/i, label: 'Sysinfo key: Current JarFile Path (Java-based)' },
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
      { pattern: /ailurophile/i, label: 'Self-ID: Ailurophile' },
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
    sysinfoKeys: [
      { pattern: /^FileLocation$/i, label: 'Sysinfo key: FileLocation' },
      { pattern: /^Current Language$/i, label: 'Sysinfo key: Current Language' },
      { pattern: /^MachineName$/i, label: 'Sysinfo key: MachineName' },
      { pattern: /^Hardwares$/i, label: 'Sysinfo key: Hardwares' },
    ],
    sysinfoContent: [
      { pattern: /ArechClient/i, label: 'Sysinfo content: ArechClient branding' },
    ],
    folders: [
      { pattern: /^Browser$/i, label: 'Folder: Browser/' },
    ],
    files: [
      { pattern: /^Clipboard\.txt$/i, label: 'File: Clipboard.txt' },
      { pattern: /^ProcessList\.txt$/i, label: 'File: ProcessList.txt' },
    ],
    structures: [],
  },

  BlankGrabber: {
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^Host Name$/i, label: 'Sysinfo key: Host Name' },
      { pattern: /^System Manufacturer$/i, label: 'Sysinfo key: System Manufacturer' },
      { pattern: /^Total Physical Memory$/i, label: 'Sysinfo key: Total Physical Memory' },
    ],
    sysinfoContent: [
      { pattern: /Blank\s*Grabber/i, label: 'Sysinfo content: Blank Grabber branding' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
      { pattern: /^Cookies\.txt$/i, label: 'File: Cookies.txt' },
    ],
    structures: [],
  },

  PredatorTheThief: {
    sysinfoFile: { pattern: /^Information\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^MachineID$/i, label: 'Sysinfo key: MachineID' },
      { pattern: /^GUID$/i, label: 'Sysinfo key: GUID' },
    ],
    sysinfoContent: [
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
    sysinfoFile: { pattern: /^System(?:\s*)?Info(?:rmation)?\.txt$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [],
    sysinfoContent: [
      { pattern: /Luca\s*Stealer/i, label: 'Sysinfo content: Luca Stealer branding' },
      { pattern: /LucaStealer/i, label: 'Sysinfo content: LucaStealer branding' },
    ],
    folders: [],
    files: [
      { pattern: /^Passwords\.txt$/i, label: 'File: Passwords.txt' },
    ],
    structures: [],
  },

  SnatchAndHub: {
    selfId: [
      { pattern: /SNATCH\s*(?:&|and)\s*HUB/i, label: 'Self-ID: SNATCH & HUB' },
      { pattern: /Forzatraffic/i, label: 'Self-ID: Forzatraffic panel' },
    ],
    asciiBanners: [
      'SNATCH & HUB Motherfucker',
    ],
    sysinfoFile: null,
    sysinfoKeys: [],
    sysinfoContent: [],
    folders: [],
    files: [
      { pattern: /^passwords\.txt$/i, label: 'File: passwords.txt' },
      { pattern: /^unique[\s_-]*passwords\.txt$/i, label: 'File: unique_passwords.txt' },
      { pattern: /^domain[\s_-]*detect(?:s)?\.txt$/i, label: 'File: domain detect.txt' },
    ],
    structures: [],
  },

  WorldWind: {
    sysinfoFile: { pattern: /^pc[\s_-]*info\.(?:json|txt)$/i, weight: SIGNAL_WEIGHTS.SYSINFO_FILE },
    sysinfoKeys: [
      { pattern: /^PcName$/i, label: 'Sysinfo key: PcName' },
      { pattern: /^Hwid$/i, label: 'Sysinfo key: Hwid' },
      { pattern: /^IsElevator$/i, label: 'Sysinfo key: IsElevator' },
      { pattern: /^CpuCores$/i, label: 'Sysinfo key: CpuCores' },
    ],
    sysinfoContent: [],
    folders: [
      { pattern: /^Autofill$/i, label: 'Folder: Autofill/' },
      { pattern: /^Cookies$/i, label: 'Folder: Cookies/' },
      { pattern: /^FBFastCheck$/i, label: 'Folder: FBFastCheck/' },
    ],
    files: [
      { pattern: /^passwords\.txt$/i, label: 'File: passwords.txt' },
      { pattern: /^pc[\s_-]*info\.(?:json|txt)$/i, label: 'File: pc_info.json' },
    ],
    structures: [
      {
        test: (dirs, files) => {
          return files.some(f => /^FBFastCheck\/Token_EAAB\.txt$/i.test(f));
        },
        label: 'Structure: FBFastCheck/Token_EAAB.txt present',
      },
      {
        test: (dirs, files) => {
          const hasCookieRestore = files.some(f => /^Chrome_cookie_restore_data_\d+\.txt$/i.test(f));
          const hasNumberedCookies = files.some(f => /^Cookies\/Chrome_\d+\.txt$/i.test(f));
          return hasCookieRestore || hasNumberedCookies;
        },
        label: 'Structure: Chrome_cookie_restore_data + numbered cookies',
      },
    ],
  },
};


// File type detection patterns

export const TEXT_EXTENSIONS = /\.(txt|tsv|csv|json)$/i;

export const FILE_TYPE_PATTERNS = {
  password: {
    patterns: [
      /^(?:all|unique|icloud)[\s_-]*passwords?\.(txt|tsv|csv)$/i,
      /^passwords?\.(txt|tsv|csv)$/i,
      /^pass(?:words?)?[_-]?(?:list|dump|log)?\.(txt|tsv|csv)$/i,
      /^passwords?[_\s](?:google\s?chrome|microsoft\s?edge|firefox|opera|brave|vivaldi|chromium)[^/]*\.(txt|tsv|csv)$/i,
      /^logins?\.(txt|tsv|csv)$/i,
      /^credentials?\.(txt|tsv|csv)$/i,
      /^keychain(?:\s*data)?\.(txt|tsv|csv)$/i,
      /^brute\.txt$/i,
    ],
    exclusions: [
      /bruteforce/i,
      /wordlist/i,
    ],
    parentDirMatch: /^(?:passwords?|logins?)$/i,
  },

  cookie: {
    patterns: [
      /^cookies?\.(txt|tsv|csv|json)$/i,
      /^(?:chrome|firefox|edge)[\s_-]*cookie[\s_-]*restore[\s_-]*data[\s_-]*\d*\.txt$/i,
      /^Cookies[\s_-]*(?:JSON|Netscape)\.txt$/i,
    ],
    browserProfiles: [
      /^(?:chrome|firefox|edge|opera|brave|vivaldi|chromium)[_\s]?\d+\.txt$/i,
      /^(?:google\s?chrome|microsoft\s?edge)[_\s]?(?:default|profile)?\s*\d*\.txt$/i,
    ],
    textExtensions: TEXT_EXTENSIONS,
    excludeFolders: /^(?:auto[\s_-]*fills?|histor(?:y|ies)|downloads?|bookmarks?|passwords?|logins?|credit[\s_-]*cards?)$/i,
    parentDirMatch: /^cookies?$/i,
  },

  sysinfo: {
    filePatterns: [
      /^user[\s_-]*info(?:rmation)?\.txt$/i,
      /^system[\s_-]*info(?:rmation)?\.txt$/i,
      /^system\.txt$/i,
      /^info(?:rmation)?\.txt$/i,
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
    ],
    folderPattern: /^auto[\s_-]*fills?$/i,
  },

  history: {
    filePatterns: [
      /^history\.(txt|tsv|csv|json)$/i,
      /^browsing[\s_-]*history\.(txt|tsv|csv)$/i,
    ],
    folderPattern: /^history$/i,
  },

  screenshot: {
    namePattern: /^screenshots?\b/i,
    extensions: /\.(jpg|jpeg|png|bmp|gif|webp)$/i,
  },

  creditCard: {
    filePatterns: [
      /^(?:credit[\s_-]*)?cards?\.(txt|tsv|csv)$/i,
      /^cc[\s_-]?data\.(txt|tsv|csv)$/i,
      /^CreditCards?\.(txt|tsv|csv)$/i,
    ],
    folderPattern: /^(?:credit[\s_-]*)?cards?|credits?$/i,
  },

  cryptoWallet: {
    folderPatterns: [
      /^wallets?$/i,
      /^crypto$/i,
      /^extensions?$/i,
    ],
    filePatterns: [
      /^wallet[\s_-]*data\.(txt|json)$/i,
      /^metamask/i,
      /^token\.json$/i,
      /^seed\.txt$/i,
    ],
  },

  messenger: {
    folderPatterns: [
      /^messengers?$/i,
      /^discord$/i,
      /^telegram$/i,
      /^FBFastCheck$/i,
    ],
    filePatterns: [
      /^token[s]?\.txt$/i,
      /^discord[\s_-]*token/i,
      /^accounts\.txt$/i,
      /^Token_EAAB\.txt$/i,
      /^IDs\.txt$/i,
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
      /^installed\s*software\.txt$/i,
      /^software\.txt$/i,
      /^installed\s*programs?\.txt$/i,
      /^programs?\s*list\.txt$/i,
      /^installed\s*apps?\.txt$/i,
      /^installed\s*browsers?\.txt$/i,
    ],
  },

  processList: {
    filePatterns: [
      /^process\s*list\.txt$/i,
      /^processes?\.txt$/i,
      /^running\s*processes?\.txt$/i,
      /^tasklist\.txt$/i,
    ],
  },

  domainDetect: {
    filePatterns: [
      /^domain[\s_-]*detect(?:s)?\.txt$/i,
    ],
  },

  downloadHistory: {
    folderPattern: /^downloads?$/i,
    parentDirMatch: /^Browser$/i,
  },
};


// Session cookies (exact match → 'auth', regex → 'session')

export const AUTH_COOKIE_NAMES = new Set([
  // Generic framework session cookies
  'jsessionid', 'phpsessid', 'asp.net_sessionid', 'connect.sid',
  'laravel_session', '_rails_session', 'ci_session', 'djangosessionid',

  // Google
  'sid', 'ssid', 'hsid', 'apisid', 'sapisid',
  '__secure-1psid', '__secure-3psid',

  // Microsoft / Azure
  'estsauthpersistent', 'estsauth',

  // Facebook / Meta
  'xs', 'c_user',

  // GitHub
  'user_session', '__host-user_session_same_site', 'dotcom_user', 'logged_in',

  // Twitter / X
  'auth_token', 'ct0', 'twid',

  // Reddit
  'reddit_session', 'token_v2',

  // Amazon
  'at-main',

  // Cloudflare
  'cf_authorization',

  // Okta
  'okta-oauth-state',

  // Atlassian
  'cloud.session.token', 'tenant.session.token',

  // Generic
  'jwt', 'access_token', 'bearer_token',
]);

export const SESSION_PATTERNS = [
  /session[_-]?id$/i,
  /^session[_-]/i,
  /_session$/i,
  /^sess[_-]/i,
  /^auth[_-]?token/i,
  /^access[_-]?token/i,
  /^oauth[_-]/i,
  /^sso[_-]/i,
  /^login[_-]token/i,
];


// Field name patterns

export const FIELD_PATTERNS = {
  url:        /^(url|domain|host|site|origin)$/i,
  username:   /^(user(?:name)?|login|email|account)$/i,
  password:   /^(pass(?:word)?|pwd)$/i,
  expires:    /^(expires?|expir)/i,
  cookieDomain: /^(domain|host)$/i,
  cookieName: /^name$/i,
  email:      /email|e-mail/i,
  phone:      /phone|mobile|landline|tel/i,
  name:       /first\s*name|last\s*name|^name$|full\s*name|given|family|surname/i,
  address:    /address|street|city|state|zip|postcode|country|suburb/i,
  formField:  /^(name|form|field)$/i,
  formValue:  /^(value)$/i,
};

export const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
export const PHONE_REGEX = /^\+?\d[\d\s()-]{6,}$/;


// IOC extraction from sysinfo

export const IOC_KEY_MAP = [
  { label: 'IP Address', patterns: [/^ip$/i, /^ip\s*address$/i] },
  { label: 'Country', patterns: [/^country$/i] },
  { label: 'City', patterns: [/^city$/i] },
  { label: 'HWID', patterns: [/^hwid$/i, /^machine\s*id$/i, /^machineid$/i, /^hardware\s*uuid$/i] },
  { label: 'GUID', patterns: [/^guid$/i] },
  { label: 'Computer Name', patterns: [/^computer\s*name$/i, /^netbios\s*name$/i, /^netbios$/i] },
  { label: 'User Name', patterns: [/^user\s*name$/i, /^username$/i] },
  { label: 'OS', patterns: [/^os$/i, /^windows$/i, /^system\s*version$/i, /^os\s*version$/i, /^mac\s*os\s*version$/i] },
  { label: 'Malware Path', patterns: [/^running\s*path$/i, /^execution\s*path$/i, /^path$/i, /^work\s*dir$/i] },
  { label: 'Build ID', patterns: [/^build$/i, /^build\s*id$/i, /^build\s*tag$/i, /^version\s*build$/i, /^version$/i] },
  { label: 'Log Date', patterns: [/^date$/i, /^log\s*date$/i, /^system\s*date$/i, /^local\s*time$/i, /^current\s*time$/i, /^time$/i] },
  { label: 'Antivirus', patterns: [/^antivirus$/i, /^av$/i, /^installed\s*av$/i] },
  { label: 'Product Key', patterns: [/^product\s*key$/i] },
  { label: 'Display Resolution', patterns: [/^display\s*resolution$/i, /^resolution$/i, /^screen\s*resolution$/i] },
  { label: 'Timezone', patterns: [/^time\s*zone$/i, /^timezone$/i, /^utc$/i] },
  { label: 'Language', patterns: [/^language$/i, /^system\s*language$/i, /^keyboard\s*layout$/i] },
  { label: 'Tracker', patterns: [/^traffic$/i, /^tracker$/i, /^tag$/i] },
];

// Content-based IOC patterns (applied to raw sysinfo text)
export const CONTENT_IOC_PATTERNS = [
  { label: 'C2/Panel URL', pattern: /https?:\/\/[^\s"'<>]{5,}/gi },
  { label: 'Telegram Contact', pattern: /(?<![a-zA-Z0-9._%+-])@[a-zA-Z_]\w{3,}/g },
  { label: 'Telegram Channel', pattern: /t\.me\/[a-zA-Z_]\w{3,}/gi },
  { label: 'Malware Signature', pattern: /\(sig:[0-9a-f]+\.[0-9a-f]+\)/gi },
];

export const CAPTURE_TIME_KEYS = [
  /^date$/i,
  /^log\s*date$/i,
  /^system\s*date$/i,
  /^local\s*time$/i,
  /^current\s*time$/i,
  /^time$/i,
  /^timestamp$/i,
  /^infection\s*date$/i,
  /^stolen\s*time$/i,
  /^capture\s*date$/i,
];

export const IGNORE_DATE_KEYS = [
  /^build\s*date$/i,
  /^install\s*date$/i,
];


// Sysinfo → identity mapping

export const IDENTITY_SYSINFO_KEYS = {
  osUsername:    [/^user\s*name$/i, /^username$/i],
  computerName: [/^computer\s*name$/i, /^netbios/i],
  country:      [/^country$/i],
};


// Limits

export const LIMITS = {
  topDomains: 15,
  topUsernames: 15,
  topCookieDomains: 15,
  topTimelineCookieDomains: 20,
  topHistoryDomainsPerDay: 5,
  maxAutofillOther: 20,
};
