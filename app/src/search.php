<?php
require __DIR__ . '/bootstrap.php';

$q       = (string)($_GET['q'] ?? '');
$rows    = [];
$dbError = '';

if ($q !== '') {
    // VULNERABILITY: SQL injection. CWE-89. $q is concatenated straight into
    // the statement, so a single quote closes the string literal and everything
    // after it is parsed as SQL by the server.
    //   Try:  ' OR '1'='1
    //         ' UNION SELECT 1,username,password_hash,1 FROM users -- -
    // FIX: $st = db()->prepare("SELECT id, name, category, price_cents FROM
    //      products WHERE name LIKE ? ORDER BY name");
    //      $st->execute(['%' . $q . '%']);
    // Escaping the input is not the fix. Separating code from data is the fix.
    $sql = "SELECT id, name, category, price_cents FROM products "
         . "WHERE name LIKE '%" . $q . "%' ORDER BY name";
    try {
        $rows = db()->query($sql)->fetchAll();
        Log::set('outcome', 'search_ok');
    } catch (PDOException $e) {
        // VULNERABILITY: verbose error disclosure. CWE-209. Echoing the driver
        // message hands an attacker the column count, table names and syntax
        // context that turn blind injection into a five minute job.
        // FIX: log the detail, show the user a generic failure message.
        $dbError = $e->getMessage();
        Log::set('outcome', 'search_db_error');
        Log::set('db_error', $dbError);
    }
} else {
    Log::set('outcome', 'search_empty');
}

page_top('Search parts');
echo '<form method="get" action="/search.php">'
   . '<input name="q" value="' . h($q) . '" size="55"> <button>Search</button></form>';

if ($dbError !== '') {
    echo '<p class="err">SQL error: ' . h($dbError) . '</p>';
}

if ($q !== '' && $dbError === '') {
    echo '<p>' . count($rows) . ' result(s) for <code>' . h($q) . '</code>.</p>';
    echo '<table><tr><th>Name</th><th>Category</th><th>Price</th></tr>';
    foreach ($rows as $r) {
        // Output here IS escaped. The defect on this page is the query, not the
        // rendering. One vulnerability per endpoint keeps the WAF results
        // interpretable later.
        echo '<tr><td><a href="/product.php?id=' . (int)$r['id'] . '">'
           . h((string)$r['name']) . '</a></td>'
           . '<td>' . h((string)$r['category']) . '</td>'
           . '<td>' . money((int)$r['price_cents']) . '</td></tr>';
    }
    echo '</table>';
}
page_end();
