// Справочники портов. Сам по себе порт не считается угрозой: эти списки
// используются только как контекст для поведенческих детекторов.

// Сервисы аутентификации и удалённого доступа: повторные попытки — признак подбора.
export const AUTH_PORTS = new Set([21, 22, 23, 110, 143, 389, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986]);

// Порты, исторически связанные с бэкдорами, IRC-ботнетами и Tor.
export const SUSPICIOUS_PORTS = new Set([1337, 4444, 6666, 6667, 6697, 9001, 9050, 12345, 27374, 31337]);

// Штатно периодические службы — исключаются из поиска C2-маяков.
export const PERIODIC_OK = new Set([53, 67, 68, 123, 137, 138, 161, 162, 514, 1900, 5353, 5355]);

export const SERVICES = {
  20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
  80: 'HTTP', 110: 'POP3', 123: 'NTP', 135: 'MS-RPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS',
  143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
  587: 'SMTP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MS SQL', 1521: 'Oracle', 1900: 'SSDP',
  3306: 'MySQL', 3389: 'RDP', 4444: 'Metasploit', 5353: 'mDNS', 5355: 'LLMNR', 5432: 'PostgreSQL',
  5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM', 6379: 'Redis', 6667: 'IRC', 8080: 'HTTP-alt',
  8443: 'HTTPS-alt', 9001: 'Tor', 9050: 'Tor', 27017: 'MongoDB', 31337: 'Back Orifice',
};

export function serviceName(port) {
  return SERVICES[port] || (port ? String(port) : '—');
}
