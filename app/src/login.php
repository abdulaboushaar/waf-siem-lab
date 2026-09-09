<?php
require __DIR__ . '/bootstrap.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = (string)($_POST['username'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    Log::set('user', $username !== '' ? $username : null);

    // VULNERABILITY: no throttling of authentication attempts. CWE-307
    // (Improper Restriction of Excessive Authentication Attempts). Nothing
    // counts failures per account or per source address, so an attacker can
    // run a whole wordlist at whatever rate the server will answer.
    // FIX: track failures keyed by username and by client IP in the database
    // or a cache, then apply exponential backoff or a temporary lockout once a
    // small threshold is crossed.

    try {
        $st = db()->prepare('SELECT username, password_hash, role FROM users WHERE username = ?');
        $st->execute([$username]);
        $row = $st->fetch();

        if ($row === false) {
            // VULNERABILITY: observable response discrepancy. CWE-204. Saying
            // "no such user" confirms the account does not exist, letting an
            // attacker enumerate valid usernames before spending any guesses
            // on passwords.
            // FIX: return one identical message for both failure branches, and
            // run password_verify against a dummy hash when the user is missing
            // so the response timing matches too.
            $error = 'No such user.';
            Log::set('outcome', 'login_failed_unknown_user');
        } elseif (!password_verify($password, (string)$row['password_hash'])) {
            // Same CWE-204 defect, other half. The wording differs from the
            // branch above, and that difference is the whole vulnerability.
            $error = 'Wrong password for that user.';
            Log::set('outcome', 'login_failed_bad_password');
        } else {
            // Correct practice, kept on purpose: rotating the session id at
            // privilege change defeats session fixation (CWE-384).
            session_regenerate_id(true);
            $_SESSION['user'] = $row['username'];
            $_SESSION['role'] = $row['role'];
            Log::set('role', $row['role']);
            Log::set('outcome', 'login_ok');
            header('Location: /index.php');
            return;
        }
    } catch (PDOException $e) {
        $error = 'Database error.';
        Log::set('outcome', 'login_db_error');
        Log::set('db_error', $e->getMessage());
    }
} else {
    Log::set('outcome', 'login_form');
}

page_top('Login');
if ($error !== '') {
    echo '<p class="err">' . h($error) . '</p>';
}
echo '<form method="post" action="/login.php">'
   . '<p>Username <input name="username" autocomplete="off"></p>'
   . '<p>Password <input name="password" type="password" autocomplete="off"></p>'
   . '<p><button>Sign in</button></p></form>';
page_end();
