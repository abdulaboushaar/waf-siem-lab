<?php
declare(strict_types=1);

// Shared request context, database handle, and the single structured log line
// that every request emits. Included first by every endpoint.

const LOG_PATH  = '/var/log/app/app.log';
const SPECS_DIR = '/var/www/specs/';

session_start();

// SECURITY-RELEVANT: X-Forwarded-For is attacker controlled unless a trusted
// reverse proxy rewrites it. We take the first value because the WAF in Step 2
// sets it, but nothing here verifies the request actually came through the WAF.
// A real deployment pins the trusted proxy address and walks the header from
// the right, discarding hops the proxy did not add itself.
function client_ip(): string
{
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    if ($xff !== '') {
        $first = trim(explode(',', $xff)[0]);
        if ($first !== '') {
            return $first;
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

final class Log
{
    private static array $e = [];

    public static function init(): void
    {
        self::$e = [
            'ts'         => (new DateTimeImmutable('now', new DateTimeZone('UTC')))
                                ->format('Y-m-d\TH:i:s.vP'),
            'request_id' => $_SERVER['HTTP_X_LAB_REQUEST_ID'] ?? 'none',
            'method'     => $_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN',
            'path'       => parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/',
            'client_ip'  => client_ip(),
            'user'       => null,
            'role'       => null,
            'outcome'    => 'unhandled',
            'db_error'   => null,
        ];
        // Registered here so exactly one line is written even when the script
        // dies on a fatal error or an uncaught exception. An outcome of
        // "unhandled" in the log means something crashed before setting one.
        register_shutdown_function([self::class, 'flush']);
    }

    public static function set(string $key, mixed $value): void
    {
        self::$e[$key] = $value;
    }

    public static function flush(): void
    {
        // SECURITY-RELEVANT: attacker-controlled values (path, db_error) go into
        // this line. json_encode escapes newlines and quotes, which is what stops
        // an attacker from forging an extra log record (CWE-117, log injection).
        // Never build this line with string concatenation.
        $line = json_encode(
            self::$e,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
        );
        // O_APPEND writes below PIPE_BUF are atomic on Linux; LOCK_EX is belt
        // and braces so the normalizer never reads a half-written line.
        @file_put_contents(LOG_PATH, $line . "\n", FILE_APPEND | LOCK_EX);
    }
}

Log::init();

if (isset($_SESSION['user'])) {
    Log::set('user', $_SESSION['user']);
    Log::set('role', $_SESSION['role'] ?? null);
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $dsn = sprintf(
        'mysql:host=%s;port=3306;dbname=%s;charset=utf8mb4',
        getenv('DB_HOST') ?: 'db',
        getenv('DB_NAME') ?: 'shop'
    );
    $pdo = new PDO($dsn, getenv('DB_USER') ?: 'shop', getenv('DB_PASS') ?: '', [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        // SECURITY-RELEVANT: with emulation ON, PDO builds the final SQL string
        // client side and "prepared statement" stops meaning what you think.
        // OFF means the server parses the query before it ever sees the data,
        // which is the property that actually defeats injection.
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
    return $pdo;
}

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function money(int $cents): string
{
    return '$' . number_format($cents / 100, 2);
}

function page_top(string $title): void
{
    $u = $_SESSION['user'] ?? null;
    echo '<!doctype html><html><head><meta charset="utf-8"><title>' . h($title) . '</title>';
    echo '<style>body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:860px}'
       . 'nav a{margin-right:1rem}table{border-collapse:collapse}'
       . 'td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}'
       . '.c{border-left:3px solid #ccc;padding:.25rem .75rem;margin:.5rem 0}'
       . '.err{color:#b00}code{font-size:12px}</style></head><body>';
    echo '<nav><a href="/index.php">Parts</a><a href="/search.php">Search</a>'
       . '<a href="/admin.php">Admin</a>';
    echo $u ? '<a href="/logout.php">Logout (' . h((string)$u) . ')</a>'
            : '<a href="/login.php">Login</a>';
    echo '</nav><h1>' . h($title) . '</h1>';
}

function page_end(): void
{
    echo '</body></html>';
}
