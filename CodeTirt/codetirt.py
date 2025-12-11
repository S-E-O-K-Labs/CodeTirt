"""
CodeTirt
Focus: Python, Node.js, PHP | Aggressive Security Scanner
Created by: SEOKLabs
"""

import sys
import os
import re
import ast
import time
import threading
from datetime import datetime
from itertools import cycle

# --- AYARLAR ---
TARGET_EXTS = {'.py', '.js', '.php', '.jsx', '.ts', '.tsx', '.php5', '.php7', '.phtml'}
IGNORE_DIRS = ['.git', '__pycache__', 'node_modules', 'venv', 'env', 'vendor']

class Colors:
    RED, YELLOW, GREEN, BLUE, CYAN, MAGENTA, GREY, RESET, BOLD = '\033[91m', '\033[93m', '\033[92m', '\033[94m', '\033[96m', '\033[95m', '\033[90m', '\033[0m', '\033[1m'

def print_c(text, color=Colors.RESET, end="\n"):
    sys.stdout.write(f"{color}{text}{Colors.RESET}{end}")
    sys.stdout.flush()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def animate_scan(active):
    """Animasyon gösterimi"""
    frames = ['|', '/', '-', '\\']
    spinner = cycle(frames)
    
    while active[0]:
        frame = next(spinner)
        sys.stdout.write(f"\r  {Colors.CYAN}{frame}{Colors.RESET} Scanning files...")
        sys.stdout.flush()
        time.sleep(0.1)

def print_header():
    """Başlık yazdır"""
    clear_screen()
    print_c("""
      ██████╗ ██████╗ ██████╗ ███████╗████████╗██╗██████╗ ████████╗
     ██╔════╝██╔═══██╗██╔══██╗██╔════╝╚══██╔══╝██║██╔══██╗╚══██╔══╝
     ██║     ██║   ██║██║  ██║█████╗     ██║   ██║██████╔╝   ██║   
     ██║     ██║   ██║██║  ██║██╔══╝     ██║   ██║██╔══██╗   ██║   
     ╚██████╗╚██████╔╝██████╔╝███████╗   ██║   ██║██║  ██║   ██║   
      ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═╝   ╚═╝   
    """, Colors.CYAN + Colors.BOLD)
    print_c("=" * 70, Colors.BLUE)
    print_c("Aggressive Deep Security Analysis | Python | Node.js | PHP", Colors.MAGENTA)
    print_c("=" * 70, Colors.BLUE)

# --- GENİŞLETİLMİŞ ZAFİYET VERİTABANI ---
VULN_DB = {
    '.py': [
        # SQL Injection Patterns
        (r"execute\(.*f[\"']", "CRITICAL", "SQL Injection (f-string)", "Use parameterized queries"),
        (r"execute\(.*%s?.*%", "CRITICAL", "SQL Injection (%)", "Use parameterized queries"),
        (r"executemany\(.*f[\"']", "CRITICAL", "SQL Injection (f-string)", "Use parameterized queries"),
        (r"query\(.*f[\"']", "CRITICAL", "SQL Injection (f-string)", "Use parameterized queries"),
        
        # Command Injection Patterns
        (r"subprocess\.", "HIGH", "Subprocess Usage", "Validate all inputs"),
        (r"subprocess\..*shell\s*=\s*True", "CRITICAL", "OS Command Injection", "Set shell=False"),
        (r"subprocess\..*shell\s*=\s*True.*check", "CRITICAL", "OS Command Injection", "Set shell=False"),
        (r"os\.system\(", "CRITICAL", "OS Command Injection", "Use subprocess module safely"),
        (r"os\.popen\(", "CRITICAL", "OS Command Injection", "Use subprocess module safely"),
        (r"commands\.getoutput", "CRITICAL", "OS Command Injection", "Use subprocess module"),
        
        # Code Injection Patterns
        (r"eval\(", "CRITICAL", "Code Injection (eval)", "Avoid eval() function"),
        (r"exec\(", "CRITICAL", "Code Injection (exec)", "Avoid exec() function"),
        (r"compile\(", "HIGH", "Code Compilation", "Validate source code"),
        
        # Deserialization Patterns
        (r"pickle\.load", "CRITICAL", "Insecure Deserialization", "Do not unpickle untrusted data"),
        (r"marshal\.load", "CRITICAL", "Insecure Deserialization", "Avoid marshal module"),
        (r"yaml\.load\(", "HIGH", "Unsafe YAML Load", "Use yaml.safe_load()"),
        
        # File Operations
        (r"open\(.*\.\.", "HIGH", "Path Traversal", "Validate file paths"),
        (r"open\(.*/\.\.", "HIGH", "Path Traversal", "Validate file paths"),
        
        # Web Framework Issues
        (r"flask\.run\(.*debug\s*=", "MEDIUM", "Debug Mode", "Disable debug in production"),
        (r"app\.run\(.*debug\s*=", "MEDIUM", "Debug Mode", "Disable debug in production"),
        (r"DEBUG\s*=\s*True", "MEDIUM", "Debug Mode", "Set DEBUG=False in production"),
        
        # Input Handling
        (r"input\(", "MEDIUM", "User Input", "Validate and sanitize input"),
        (r"raw_input\(", "MEDIUM", "User Input", "Validate and sanitize input"),
        
        # Weak Cryptography
        (r"hashlib\.md5\(", "MEDIUM", "Weak Hash (MD5)", "Use SHA-256 or bcrypt"),
        (r"hashlib\.sha1\(", "MEDIUM", "Weak Hash (SHA1)", "Use SHA-256 or stronger"),
        (r"random\.", "MEDIUM", "Insecure Random", "Use secrets module for crypto"),
    ],
    
    '.js': [
        # Code Injection Patterns
        (r"eval\(", "CRITICAL", "Code Injection (eval)", "Avoid eval() function"),
        (r"Function\(", "CRITICAL", "Code Injection (Function)", "Avoid Function constructor"),
        (r"setTimeout\(.*,.*['\"]", "HIGH", "Code Injection", "Use function references"),
        (r"setInterval\(.*,.*['\"]", "HIGH", "Code Injection", "Use function references"),
        
        # Command Injection Patterns
        (r"child_process\.exec\(", "CRITICAL", "OS Command Injection", "Use execFile or spawn"),
        (r"child_process\.execSync\(", "CRITICAL", "OS Command Injection", "Use execFile or spawn"),
        (r"child_process\.spawn\(.*shell", "HIGH", "OS Command Injection", "Avoid shell mode"),
        
        # NoSQL Injection
        (r"\$where", "CRITICAL", "NoSQL Injection", "Avoid $where operator"),
        (r"where\(.*function", "CRITICAL", "NoSQL Injection", "Avoid functions in where"),
        
        # XSS Patterns
        (r"\.innerHTML\s*=", "HIGH", "DOM XSS", "Use textContent or sanitize"),
        (r"\.outerHTML\s*=", "HIGH", "DOM XSS", "Use textContent or sanitize"),
        (r"document\.write\(", "HIGH", "DOM XSS", "Avoid document.write"),
        (r"\.write\(", "HIGH", "DOM XSS", "Avoid document.write"),
        
        # Response Handling
        (r"res\.send\(.*req\.", "HIGH", "Reflected XSS", "Sanitize output"),
        (r"res\.write\(.*req\.", "HIGH", "Reflected XSS", "Sanitize output"),
        (r"res\.end\(.*req\.", "HIGH", "Reflected XSS", "Sanitize output"),
        
        # File Operations
        (r"fs\.readFile\(.*req\.", "HIGH", "Path Traversal", "Validate file paths"),
        (r"fs\.readFileSync\(.*req\.", "HIGH", "Path Traversal", "Validate file paths"),
        (r"fs\.writeFile\(.*req\.", "HIGH", "Path Traversal", "Validate file paths"),
        (r"require\(.*\.\.", "HIGH", "Path Traversal", "Avoid dynamic require"),
        
        # JWT Issues
        (r"jwt\.sign\(.*algorithm.*none", "CRITICAL", "JWT None Algorithm", "Enforce strong algorithms"),
        (r"jwt\.verify\(.*algorithm.*none", "CRITICAL", "JWT None Algorithm", "Enforce strong algorithms"),
        
        # Prototype Pollution
        (r"__proto__", "MEDIUM", "Prototype Pollution", "Validate objects"),
        (r"prototype\.", "MEDIUM", "Prototype Pollution", "Avoid direct modification"),
        (r"constructor\.prototype", "MEDIUM", "Prototype Pollution", "Avoid modification"),
        
        # Weak Cryptography
        (r"crypto\.createHash\(.*md5", "MEDIUM", "Weak Hash (MD5)", "Use SHA-256"),
        (r"crypto\.createHash\(.*sha1", "MEDIUM", "Weak Hash (SHA1)", "Use SHA-256"),
        (r"Math\.random\(", "MEDIUM", "Insecure Random", "Use crypto.randomBytes"),
        
        # Storage Issues
        (r"localStorage\.setItem\(.*pass", "HIGH", "Insecure Storage", "Avoid storing secrets"),
        (r"localStorage\.setItem\(.*secret", "HIGH", "Insecure Storage", "Avoid storing secrets"),
        (r"sessionStorage\.setItem\(.*pass", "HIGH", "Insecure Storage", "Avoid storing secrets"),
        
        # Logging Issues
        (r"console\.log\(.*pass", "LOW", "Sensitive Logging", "Remove from logs"),
        (r"console\.log\(.*secret", "LOW", "Sensitive Logging", "Remove from logs"),
    ],
    
    '.php': [
        # RCE Functions
        (r"system\(", "CRITICAL", "RCE Function (system)", "Disable in php.ini"),
        (r"shell_exec\(", "CRITICAL", "RCE Function (shell_exec)", "Disable in php.ini"),
        (r"passthru\(", "CRITICAL", "RCE Function (passthru)", "Disable in php.ini"),
        (r"exec\(", "CRITICAL", "RCE Function (exec)", "Disable in php.ini"),
        (r"proc_open\(", "CRITICAL", "RCE Function (proc_open)", "Disable in php.ini"),
        (r"popen\(", "CRITICAL", "RCE Function (popen)", "Disable in php.ini"),
        
        # Code Injection
        (r"eval\(", "CRITICAL", "Code Injection (eval)", "Do not use eval()"),
        (r"assert\(", "CRITICAL", "Code Injection (assert)", "Do not use assert()"),
        (r"create_function\(", "CRITICAL", "Code Injection", "Use anonymous functions"),
        
        # File Inclusion
        (r"include\(", "HIGH", "File Inclusion", "Validate paths"),
        (r"require\(", "HIGH", "File Inclusion", "Validate paths"),
        (r"include_once\(", "HIGH", "File Inclusion", "Validate paths"),
        (r"require_once\(", "HIGH", "File Inclusion", "Validate paths"),
        
        # SQL Injection
        (r"mysql_query\(", "CRITICAL", "SQL Injection (mysql)", "Use PDO or mysqli"),
        (r"mysqli_query\(", "HIGH", "SQL Injection (mysqli)", "Use prepared statements"),
        (r"pg_query\(", "HIGH", "SQL Injection (pgsql)", "Use prepared statements"),
        
        # XSS Patterns
        (r"echo\s*\$_", "HIGH", "XSS Risk", "Escape with htmlspecialchars"),
        (r"print\s*\$_", "HIGH", "XSS Risk", "Escape with htmlspecialchars"),
        (r"printf\s*\$_", "HIGH", "XSS Risk", "Escape with htmlspecialchars"),
        
        # Input Handling
        (r"\$_GET\[", "MEDIUM", "GET Input", "Use filter_input()"),
        (r"\$_POST\[", "MEDIUM", "POST Input", "Use filter_input()"),
        (r"\$_REQUEST\[", "MEDIUM", "REQUEST Input", "Use filter_input()"),
        (r"\$_COOKIE\[", "MEDIUM", "COOKIE Input", "Use filter_input()"),
        
        # File Operations
        (r"file_get_contents\(.*\$_", "HIGH", "SSRF/LFI Risk", "Validate URLs"),
        (r"file_put_contents\(.*\$_", "HIGH", "File Write Risk", "Validate paths"),
        (r"fopen\(.*\$_", "HIGH", "File Open Risk", "Validate paths"),
        
        # Deserialization
        (r"unserialize\(", "CRITICAL", "Insecure Deserialization", "Do not unserialize user data"),
        
        # Regex Injection
        (r"preg_replace\(.*/e", "CRITICAL", "Code Injection", "Remove /e modifier"),
        
        # Variable Injection
        (r"extract\(", "HIGH", "Variable Injection", "Avoid extract()"),
        (r"parse_str\(", "HIGH", "Variable Injection", "Validate input"),
        
        # Weak Cryptography
        (r"md5\(", "MEDIUM", "Weak Hash (MD5)", "Use password_hash()"),
        (r"sha1\(", "MEDIUM", "Weak Hash (SHA1)", "Use password_hash()"),
        (r"rand\(", "MEDIUM", "Insecure Random", "Use random_int()"),
        (r"mt_rand\(", "MEDIUM", "Insecure Random", "Use random_int()"),
        
        # Error Handling
        (r"error_reporting\(0\)", "MEDIUM", "Error Suppression", "Handle errors properly"),
        (r"@\s*", "LOW", "Error Suppression", "Avoid @ operator"),
        
        # Info Disclosure
        (r"phpinfo\(", "LOW", "Info Disclosure", "Remove from production"),
    ],
}

# Aggressive Secret Patterns
SECRET_PATTERNS = [
    # API Keys and Secrets
    (r"(api.?key|apikey|api.key)\s*=.*['\"].{10,}['\"]", "CRITICAL", "Hardcoded API Key"),
    (r"(secret.?key|secretkey|secret.key)\s*=.*['\"].{10,}['\"]", "CRITICAL", "Hardcoded Secret Key"),
    (r"(private.?key|privatekey|private.key)\s*=.*['\"].{10,}['\"]", "CRITICAL", "Hardcoded Private Key"),
    
    # Passwords
    (r"(password|passwd|pwd)\s*=.*['\"].{6,}['\"]", "HIGH", "Hardcoded Password"),
    (r"(db.?password|dbpassword|db.pass)\s*=.*['\"].{6,}['\"]", "CRITICAL", "Database Password"),
    
    # Tokens
    (r"(auth.?token|authtoken|auth.token)\s*=.*['\"].{10,}['\"]", "CRITICAL", "Hardcoded Auth Token"),
    (r"(access.?token|accesstoken|access.token)\s*=.*['\"].{10,}['\"]", "CRITICAL", "Hardcoded Access Token"),
    (r"(refresh.?token|refreshtoken|refresh.token)\s*=.*['\"].{10,}['\"]", "CRITICAL", "Hardcoded Refresh Token"),
    
    # Database Credentials
    (r"(db.?host|dbhost)\s*=.*['\"].{5,}['\"]", "HIGH", "Database Host"),
    (r"(db.?user|dbuser)\s*=.*['\"].{3,}['\"]", "HIGH", "Database User"),
    (r"(db.?name|dbname)\s*=.*['\"].{3,}['\"]", "MEDIUM", "Database Name"),
    
    # Specific Service Keys
    (r"AIza[0-9A-Za-z\\-_]{35}", "CRITICAL", "Google API Key"),
    (r"sk_(live|test)_[0-9a-zA-Z]{24}", "CRITICAL", "Stripe Secret Key"),
    (r"rk_(live|test)_[0-9a-zA-Z]{24}", "CRITICAL", "Razorpay Secret Key"),
    (r"sq0csp-[0-9A-Za-z\\-_]{43}", "CRITICAL", "Square OAuth Secret"),
    (r"xox[pbaors]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}", "CRITICAL", "Slack Token"),
    
    # Private Keys
    (r"-----BEGIN.*PRIVATE KEY-----", "CRITICAL", "Private Key in Code"),
    (r"-----BEGIN.*RSA PRIVATE KEY-----", "CRITICAL", "RSA Private Key"),
    
    # AWS Keys
    (r"AKIA[0-9A-Z]{16}", "CRITICAL", "AWS Access Key"),
    (r"ASIA[0-9A-Z]{16}", "CRITICAL", "AWS Temporary Access Key"),
    
    # GitHub Tokens
    (r"gh[pousr]_[0-9a-zA-Z]{36}", "CRITICAL", "GitHub Token"),
    
    # JWT Tokens
    (r"eyJhbGciOiJ[^\"]{50,}", "HIGH", "JWT Token in Code"),
    
    # Generic Secrets
    (r"['\"].{20,}['\"]\s*#.*(key|secret|pass|token)", "MEDIUM", "Possible Secret in Comment"),
]

def is_comment(line, ext):
    """Basit yorum kontrolü - false positive'ı azaltmak için basitleştirildi"""
    l = line.strip()
    if not l:
        return True
    
    # Çok kısa satırları atla
    if len(l) < 3:
        return True
    
    # Çok uzun satırları atla (genellikle data veya minified kod)
    if len(l) > 200:
        return True
    
    if ext == '.py':
        return l.startswith('#')
    elif ext in ['.js', '.jsx', '.ts', '.tsx']:
        return l.startswith('//') or (l.startswith('/*') and '*/' not in l[:10])
    elif ext in ['.php', '.php5', '.php7', '.phtml']:
        return l.startswith('//') or l.startswith('#') or (l.startswith('/*') and '*/' not in l[:10])
    
    return False

def scan_file_aggressive(filepath):
    """Agresif dosya tarama"""
    vulns = []
    ext = os.path.splitext(filepath)[1].lower()
    filename = os.path.basename(filepath)
    line_count = 0
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
            line_count = len(lines)
        
        print_c(f"  Analyzing: {filename} ({line_count} lines)", Colors.GREY)
        
        # Tüm satırları tara
        for i, line in enumerate(lines):
            line_num = i + 1
            original_line = line.rstrip()
            
            # Çok kısa veya çok uzun satırları atla
            if len(original_line) < 2 or len(original_line) > 500:
                continue
            
            # Basit yorum kontrolü
            if is_comment(original_line, ext):
                continue
            
            # Zafiyet pattern'lerini kontrol et
            rules = VULN_DB.get(ext, [])
            for pattern, risk, name, fix in rules:
                try:
                    # Case-insensitive ve daha geniş arama
                    if re.search(pattern, original_line, re.IGNORECASE):
                        # Bazı false positive'ları filtrele
                        if 'htmlspecialchars' in original_line or 'filter_input' in original_line:
                            continue
                        if 'password_hash' in original_line or 'PDO::' in original_line:
                            continue
                        if 'prepared' in original_line.lower() or 'parameterized' in original_line.lower():
                            continue
                        
                        vulns.append({
                            'file': filename,
                            'line': line_num,
                            'type': name,
                            'risk': risk,
                            'code': original_line[:100],
                            'fix': fix
                        })
                        
                        # Bulunan zafiyeti göster
                        color = Colors.RED if risk == 'CRITICAL' else Colors.YELLOW
                        print_c(f"    Found {risk}: {name} at line {line_num}", color)
                        break  # Aynı satırda birden fazla pattern için tekrar ekleme
                        
                except re.error:
                    continue
            
            # Secret pattern'lerini kontrol et
            for pattern, risk, name in SECRET_PATTERNS:
                try:
                    if re.search(pattern, original_line, re.IGNORECASE):
                        # Hassas veriyi maskele
                        masked_line = re.sub(
                            r"['\"].{15,}['\"]",
                            "'***MASKED***'",
                            original_line
                        )
                        vulns.append({
                            'file': filename,
                            'line': line_num,
                            'type': name,
                            'risk': risk,
                            'code': masked_line[:100],
                            'fix': 'Use environment variables or secure vault'
                        })
                        
                        print_c(f"    Found {risk} secret: {name} at line {line_num}", Colors.RED)
                        break
                        
                except re.error:
                    continue
        
        if vulns:
            print_c(f"  Total issues in {filename}: {len(vulns)}", Colors.YELLOW)
        else:
            print_c(f"  No issues found in {filename}", Colors.GREEN)
        
    except Exception as e:
        print_c(f"  Error reading {filename}: {str(e)}", Colors.RED)
    
    return vulns, line_count

def display_results_detailed(vulns, stats, target):
    """Detaylı sonuç gösterimi"""
    print_c("\n" + "=" * 70, Colors.CYAN + Colors.BOLD)
    print_c("SECURITY SCAN RESULTS", Colors.CYAN + Colors.BOLD)
    print_c("=" * 70, Colors.CYAN)
    
    print_c(f"\nScan Summary:", Colors.BLUE)
    print_c(f"  Target: {target}", Colors.GREY)
    print_c(f"  Files Scanned: {stats['files']}", Colors.GREY)
    print_c(f"  Lines Analyzed: {stats['lines']:,}", Colors.GREY)
    print_c(f"  Scan Time: {stats['time']:.2f} seconds", Colors.GREY)
    
    if not vulns:
        print_c("\n" + "-" * 70, Colors.GREEN)
        print_c("SECURITY ASSESSMENT: CLEAN", Colors.GREEN + Colors.BOLD)
        print_c("No security vulnerabilities detected.", Colors.GREEN)
        return
    
    # İstatistikler
    risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for v in vulns:
        risk_counts[v['risk']] += 1
    
    total_issues = len(vulns)
    
    print_c("\n" + "-" * 70, Colors.YELLOW)
    print_c("VULNERABILITY SUMMARY:", Colors.YELLOW + Colors.BOLD)
    print_c(f"  Total Issues Found: {total_issues}", Colors.RED if total_issues > 0 else Colors.GREEN)
    
    for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = risk_counts[risk]
        if count > 0:
            color = Colors.RED if risk == 'CRITICAL' else Colors.YELLOW if risk == 'HIGH' else Colors.MAGENTA
            bar = "█" * min(count, 30)
            print_c(f"  {risk}: {count} {bar}", color)
    
    # Güvenlik skoru
    score = 100
    weights = {'CRITICAL': 15, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 2}
    for v in vulns:
        score -= weights.get(v['risk'], 0)
    score = max(0, score)
    
    print_c("\n" + "-" * 70, Colors.CYAN)
    print_c("SECURITY SCORE:", Colors.CYAN + Colors.BOLD)
    
    score_bar = int((score / 100) * 20)
    bar = "█" * score_bar + "░" * (20 - score_bar)
    score_color = Colors.GREEN if score >= 80 else Colors.YELLOW if score >= 60 else Colors.RED
    print_c(f"  {bar} {score}/100", score_color)
    
    # Tüm bulguları göster (kritik ve yüksek öncelikli)
    print_c("\n" + "=" * 70, Colors.RED)
    print_c("DETAILED FINDINGS:", Colors.RED + Colors.BOLD)
    
    # Dosya bazında grupla
    file_groups = {}
    for v in vulns:
        file_groups.setdefault(v['file'], []).append(v)
    
    # Önce kritik ve yüksek riskli dosyaları göster
    displayed_files = 0
    for filename in sorted(file_groups.keys()):
        file_vulns = file_groups[filename]
        
        # Sadece kritik/yüksek risk içeren dosyaları göster
        if not any(v['risk'] in ['CRITICAL', 'HIGH'] for v in file_vulns):
            continue
        
        displayed_files += 1
        if displayed_files > 10:  # Maksimum 10 dosya göster
            print_c(f"\n  ... and {len(file_groups) - displayed_files + 1} more files", Colors.GREY)
            break
        
        print_c(f"\n  File: {filename}", Colors.BLUE + Colors.BOLD)
        
        for v in file_vulns:
            if v['risk'] in ['CRITICAL', 'HIGH']:
                color = Colors.RED if v['risk'] == 'CRITICAL' else Colors.YELLOW
                print_c(f"\n    Line {v['line']}: [{v['risk']}] {v['type']}", color)
                print_c(f"      Code: {v['code']}", Colors.GREY)
                print_c(f"      Fix: {v['fix']}", Colors.CYAN)
    
    # Eğer hiç kritik/yüksek yoksa, orta risklileri göster
    if displayed_files == 0:
        print_c("\n  No critical or high risk issues found.", Colors.GREEN)
        print_c("  Medium and low risk issues:", Colors.MAGENTA)
        
        for filename in sorted(file_groups.keys())[:5]:  # İlk 5 dosya
            file_vulns = file_groups[filename]
            medium_vulns = [v for v in file_vulns if v['risk'] == 'MEDIUM']
            
            if medium_vulns:
                print_c(f"\n  File: {filename}", Colors.BLUE)
                for v in medium_vulns[:3]:  # İlk 3 orta risk
                    print_c(f"    Line {v['line']}: {v['type']}", Colors.MAGENTA)
    
    # Öneriler
    print_c("\n" + "=" * 70, Colors.GREEN)
    print_c("RECOMMENDATIONS:", Colors.GREEN + Colors.BOLD)
    
    if risk_counts['CRITICAL'] > 0:
        print_c(f"  1. IMMEDIATELY fix {risk_counts['CRITICAL']} CRITICAL issues", Colors.RED)
    if risk_counts['HIGH'] > 0:
        print_c(f"  2. Address {risk_counts['HIGH']} HIGH risk issues urgently", Colors.YELLOW)
    if risk_counts['MEDIUM'] > 0:
        print_c(f"  3. Review {risk_counts['MEDIUM']} MEDIUM risk issues", Colors.MAGENTA)
    
    print_c("  4. Implement all suggested fixes above", Colors.CYAN)
    print_c("  5. Consider professional security audit", Colors.BLUE)
    
    print_c("\n" + "=" * 70, Colors.GREEN)
    print_c("SCAN COMPLETED", Colors.GREEN + Colors.BOLD)

def scan_directory_aggressive(target_path):
    """Agresif dizin tarama"""
    all_vulns = []
    total_files = 0
    total_lines = 0
    start_time = time.time()
    
    # Animasyonu başlat
    active = [True]
    spinner_thread = threading.Thread(target=animate_scan, args=(active,))
    spinner_thread.start()
    
    try:
        # Dosyaları bul
        time.sleep(0.5)
        target_files = []
        
        if os.path.isfile(target_path):
            target_files = [target_path]
        else:
            for root, dirs, files in os.walk(target_path):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in TARGET_EXTS:
                        target_files.append(os.path.join(root, file))
        
        active[0] = False
        spinner_thread.join()
        
        print_c(f"\nFound {len(target_files)} target files", Colors.BLUE)
        
        if not target_files:
            print_c("No target files found to scan", Colors.YELLOW)
            return all_vulns, {'files': 0, 'lines': 0, 'time': 0}
        
        # Her dosyayı tara
        print_c("\nStarting aggressive security scan...\n", Colors.CYAN)
        
        for idx, filepath in enumerate(target_files, 1):
            # İlerleme göstergesi
            percent = (idx / len(target_files)) * 100
            bar_length = 40
            filled = int(bar_length * idx // len(target_files))
            bar = "█" * filled + "░" * (bar_length - filled)
            
            sys.stdout.write(f"\rScanning: [{bar}] {percent:.1f}% ({idx}/{len(target_files)})")
            sys.stdout.flush()
            
            vulns, lines = scan_file_aggressive(filepath)
            all_vulns.extend(vulns)
            total_files += 1
            total_lines += lines
        
        print_c("\n\n" + "-" * 50, Colors.GREEN)
        
    except KeyboardInterrupt:
        active[0] = False
        spinner_thread.join()
        print_c("\n\nScan interrupted by user", Colors.YELLOW)
        return all_vulns, {'files': total_files, 'lines': total_lines, 'time': time.time() - start_time}
    except Exception as e:
        active[0] = False
        spinner_thread.join()
        print_c(f"\nError during scan: {str(e)}", Colors.RED)
        return all_vulns, {'files': total_files, 'lines': total_lines, 'time': time.time() - start_time}
    
    elapsed_time = time.time() - start_time
    
    print_c("Scan completed", Colors.GREEN + Colors.BOLD)
    time.sleep(0.5)
    
    return all_vulns, {'files': total_files, 'lines': total_lines, 'time': elapsed_time}

def main():
    print_header()
    
    if len(sys.argv) < 2:
        print_c("\nUsage: python codetirt.py <file_or_directory>", Colors.YELLOW)
        print_c("\nExamples:", Colors.BLUE)
        print_c("  python codetirt.py app.py")
        print_c("  python codetirt.py /path/to/project")
        print_c("\nNote: Using aggressive scanning mode", Colors.RED)
        return
    
    target = sys.argv[1]
    
    if not os.path.exists(target):
        print_c(f"\nError: Target '{target}' not found", Colors.RED)
        return
    
    try:
        # Taramayı başlat
        print_c("\n" + "=" * 70, Colors.CYAN)
        print_c("INITIATING AGGRESSIVE SECURITY SCAN", Colors.CYAN + Colors.BOLD)
        print_c("=" * 70, Colors.CYAN)
        time.sleep(0.5)
        
        vulns, stats = scan_directory_aggressive(target)
        
        # Sonuçları göster
        print_c("\n" * 2)
        display_results_detailed(vulns, stats, target)
        
        # Rapor kaydetme seçeneği
        if vulns:
            print_c("\n" + "-" * 70, Colors.MAGENTA)
            save = input("Save detailed report to file? (y/n): ").strip().lower()
            
            if save == 'y':
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_name = f"security_report_{timestamp}.txt"
                
                with open(report_name, 'w', encoding='utf-8') as f:
                    f.write("CODETIRT AGGRESSIVE SECURITY SCAN REPORT\n")
                    f.write("="*60 + "\n")
                    f.write(f"Target: {target}\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Files: {stats['files']} | Lines: {stats['lines']}\n")
                    f.write("="*60 + "\n\n")
                    
                    for v in vulns:
                        f.write(f"[{v['risk']}] {v['file']}:{v['line']}\n")
                        f.write(f"Type: {v['type']}\n")
                        f.write(f"Code: {v['code']}\n")
                        f.write(f"Fix: {v['fix']}\n")
                        f.write("-"*40 + "\n")
                
                print_c(f"\nReport saved: {report_name}", Colors.GREEN)
        
        print_c("\n" + "=" * 70, Colors.CYAN)
        print_c("THANK YOU FOR USING CODETIRT", Colors.CYAN + Colors.BOLD)
        print_c("=" * 70, Colors.CYAN)
        
    except KeyboardInterrupt:
        print_c("\n\nScan cancelled", Colors.YELLOW)
    except Exception as e:
        print_c(f"\nError: {str(e)}", Colors.RED)

if __name__ == "__main__":
    main()
