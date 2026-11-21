"""Wordlists kept short on purpose: this runs on a phone in Termux."""

PATHS = [
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    "security.txt",
    ".well-known/security.txt",
    "humans.txt",
    "favicon.ico",
    ".git/HEAD",
    ".git/config",
    ".gitignore",
    ".env",
    ".env.local",
    ".env.production",
    "config.php",
    "wp-config.php",
    "composer.json",
    "package.json",
    "Dockerfile",
    "docker-compose.yml",
    "server-status",
    "actuator",
    "actuator/health",
    "actuator/env",
    "swagger.json",
    "openapi.json",
    "api-docs",
    "graphql",
    "phpinfo.php",
    "info.php",
    "test.php",
    "admin",
    "login",
    "dashboard",
    "backup",
    "backups",
    "db.sql",
    "dump.sql",
    "web.config",
    "appsettings.json",
    "index.phps",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "console",
    "trace",
    "metrics",
    "health",
    "version",
    "debug",
]

ADMIN_PATHS = ["admin", "login", "wp-login.php", "administrator", "signin", "dashboard"]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    512, 513, 514, 587, 631, 636, 873, 990, 993, 995, 1080, 1433, 1521, 1723, 1883,
    2049, 2082, 2083, 2181, 2222, 2375, 2376, 3000, 3128, 3260, 3306, 3389, 4443,
    5000, 5432, 5555, 5601, 5672, 5900, 5984, 6379, 6443, 7001, 8000, 8008, 8009,
    8080, 8081, 8088, 8090, 8181, 8443, 8500, 8888, 9000, 9042, 9090, 9200, 9300,
    9443, 10000, 11211, 15672, 27017, 50000,
]

HTTP_PORTS = [80, 81, 8080, 8000, 8888, 3000, 5000, 8008, 8081, 9000, 443, 8443, 9443, 4443]

SECRET_RE = (
    r"(?i)(api[_-]?key|apikey|secret|password|passwd|token|bearer|aws_|private[_-]?key|"
    r"db_pass|access[_-]?key)[^\n]{0,40}[:=]\s*[\"']?([A-Za-z0-9_\-/+.]{6,80})"
)

SENSITIVE_EXTENSIONS = (
    ".env",
    ".ini",
    ".conf",
    ".config",
    ".yml",
    ".yaml",
    ".json",
    ".php",
    ".bak",
    ".sql",
    ".log",
)
