// Synthetic logs shaped the way each family lays its output out, built from the
// layouts the signatures describe. Nothing here came from a real victim:
// addresses sit in the documentation ranges (192.0.2/24, 198.51.100/24,
// 203.0.113/24) and every site is under example.com/.org/.net.

export function passwordBlocks(rows) {
  return rows.map(({ url, user, pass, app = 'Google_[Chrome]_Default' }) => [
    `URL: ${url}`,
    `Username: ${user}`,
    `Password: ${pass}`,
    `Application: ${app}`,
    '===============',
  ].join('\n')).join('\n');
}

// Netscape cookie lines: domain, subdomains flag, path, secure, expiry (Unix
// seconds), name, value.
export function netscapeCookies(rows) {
  return rows.map(({ domain, name, value = 'v', expires, secure = 'TRUE' }) =>
    [domain, 'TRUE', '/', secure, String(expires), name, value].join('\t')).join('\n');
}

export const unix = (iso) => Math.floor(Date.parse(iso) / 1000);

export const DEFAULT_CREDENTIALS = [
  { url: 'https://mail.example.com/login', user: 'jordan.tester@example.com', pass: 'Correct-Horse-1' },
  { url: 'https://portal.example.org/', user: 'jtester', pass: 'Battery-Staple-2' },
];

export function redlineLog({
  user = 'jtester',
  country = 'AU',
  logDate = '3/14/2025 9:15:02 AM',
  timeZone = '(UTC+09:30) Adelaide',
  credentials = DEFAULT_CREDENTIALS,
  cookies = [],
} = {}) {
  const files = {
    'UserInformation.txt': [
      'Build ID: TestBuild',
      'IP: 203.0.113.10',
      `FileLocation: C:\\Users\\${user}\\AppData\\Local\\Temp\\sample.exe`,
      `UserName: ${user}`,
      `Country: ${country}`,
      'Zip Code: 5000',
      'HWID: 0123456789ABCDEF0123456789ABCDEF',
      'Current Language: English (Australia)',
      'ScreenSize: {Width=1920, Height=1080}',
      `TimeZone: ${timeZone}`,
      'Operation System: Windows 10 Pro x64',
      'UAC: AllowAll',
      'Process Elevation: False',
      `Log date: ${logDate}`,
    ].join('\n'),
    'Passwords.txt': passwordBlocks(credentials),
    'Autofills/Google_[Chrome]_Default.txt': 'Name: email\nValue: jordan.tester@example.com\n\nName: city\nValue: Adelaide\n',
  };
  if (cookies.length > 0) files['Cookies/Google_[Chrome]_Default.txt'] = netscapeCookies(cookies);
  return files;
}

export function lummaLog({
  user = 'jtester',
  localDate = '14.03.2025 09:15:02',
  credentials = DEFAULT_CREDENTIALS,
} = {}) {
  return {
    'System.txt': [
      '- LummaC2 Build: Jan 10 2025',
      '- LID (Lumma ID): T3st1ng--example',
      '- Configuration: default',
      `- Path: C:\\Users\\${user}\\AppData\\Local\\Temp\\sample.exe`,
      `- Local Date: ${localDate}`,
      '- Elevated: false',
      '- NetBIOS: DESKTOP-TEST01',
      `- User: ${user}`,
      '- Country: AU',
      '- IP: 203.0.113.20',
      '- HWID: 0123456789ABCDEF',
      '- Screen resolution: 1920x1080',
    ].join('\n'),
    'Chrome/Default/Passwords.txt': passwordBlocks(credentials),
    'Cookies/Cookies_Chrome_Default.txt': netscapeCookies([
      { domain: '.example.com', name: 'prefs', expires: unix('2026-01-01T00:00:00Z') },
    ]),
    'Screen.png': new Uint8Array([0x89, 0x50, 0x4e, 0x47]),
  };
}

export function vidarLog({ user = 'jtester', credentials = DEFAULT_CREDENTIALS } = {}) {
  return {
    'information.txt': [
      'Version: 11.2',
      'Date: 2025-03-14 09:15:02',
      'MachineID: 1a2b3c4d-0000-4000-8000-000000000001',
      'GUID: {11111111-2222-3333-4444-555555555555}',
      'HWID: 1A2B3C4D00004000800000000000000155',
      `Path: C:\\Users\\${user}\\AppData\\Local\\Temp\\sample.exe`,
      'Work Dir: C:\\ProgramData\\sample',
      '',
      'IP: 203.0.113.30',
      'Country: AU',
      'City: Adelaide',
      'ZIP: 5000',
      'ISP: Example Networks',
      '',
      `User Name: ${user}`,
      'Computer Name: DESKTOP-TEST01',
      'Display Language: en-AU',
      'Keyboard Languages: English (Australia)',
    ].join('\n'),
    'passwords.txt': passwordBlocks(credentials),
    'Autofill/Google Chrome_Default.txt': 'email jordan.tester@example.com\n',
    'Cookies/Google Chrome_Default.txt': netscapeCookies([
      { domain: '.example.com', name: 'prefs', expires: unix('2026-01-01T00:00:00Z') },
    ]),
    'History/Google Chrome_Default.txt': 'https://www.example.com/ Example\n',
    'Soft/Telegram/readme.txt': 'telegram session placeholder\n',
  };
}

export function atomicMacLog() {
  return {
    'Sysinfo.txt': [
      'Hardware Overview:',
      '  Model Name: MacBook Pro',
      '  Chip: Apple M2',
      '  Hardware UUID: 00000000-0000-4000-8000-000000000000',
      'ProductName: macOS',
      'ProductVersion: 14.4',
      'BuildVersion: 23E214',
    ].join('\n'),
    'Keychain/login.keychain-db': new Uint8Array([0x6b, 0x79, 0x63, 0x68]),
    'FileGrabber/todo.txt': 'buy milk\n',
    'Passwords.txt': passwordBlocks(DEFAULT_CREDENTIALS),
  };
}

// A resale combolist: other people's accounts, host:user:pass, no filename rule.
export function combolist(lines = 120) {
  const out = [];
  for (let i = 0; i < lines; i++) {
    out.push(`https://shop${i % 30}.example.net/login:buyer${i}@example.org:pw-${i}-x`);
  }
  return out.join('\n');
}
