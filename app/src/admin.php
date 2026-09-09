<?php
require __DIR__ . '/bootstrap.php';

// VULNERABILITY: broken access control via a client-controlled cookie.
// CWE-565 (Reliance on Cookies without Validation and Integrity Checking),
// OWASP A01:2021. The browser sends role=admin because the browser decided to.
// The server never ties this value to the authenticated session or to the
// user's role column, and the cookie carries no signature, so anyone can set it
// with document.cookie = "role=admin" or a single curl -b flag.
// FIX: read the role from $_SESSION, which lives server side and the client
// cannot edit, and re-check that user's role in the database on every
// privileged request. Never make an authorization decision from a value the
// client can rewrite.
$roleCookie = (string)($_COOKIE['role'] ?? '');
Log::set('role', $roleCookie !== '' ? $roleCookie : ($_SESSION['role'] ?? null));

if ($roleCookie !== 'admin') {
    Log::set('outcome', 'admin_denied');
    http_response_code(403);
    page_top('Admin');
    echo '<p class="err">Forbidden. Admins only.</p>';
    echo '<p><small>Lab hint: this page trusts a cookie named <code>role</code>.</small></p>';
    page_end();
    return;
}

$users = [];
try {
    $users = db()->query('SELECT id, username, role, password_hash FROM users ORDER BY id')
                 ->fetchAll();
    Log::set('outcome', 'admin_allowed');
} catch (PDOException $e) {
    Log::set('outcome', 'admin_db_error');
    Log::set('db_error', $e->getMessage());
}

page_top('Admin');
echo '<p>Account list. Reaching this page at all is the finding; the hashes are'
   . ' just there to make the impact concrete.</p>';
echo '<table><tr><th>ID</th><th>Username</th><th>Role</th><th>Password hash</th></tr>';
foreach ($users as $u) {
    echo '<tr><td>' . (int)$u['id'] . '</td>'
       . '<td>' . h((string)$u['username']) . '</td>'
       . '<td>' . h((string)$u['role']) . '</td>'
       . '<td><code>' . h((string)$u['password_hash']) . '</code></td></tr>';
}
echo '</table>';
page_end();
