<?php
require __DIR__ . '/bootstrap.php';

$rows = [];
try {
    // No user input reaches this statement.
    $rows = db()->query(
        'SELECT id, name, category, price_cents FROM products ORDER BY category, name'
    )->fetchAll();
    Log::set('outcome', 'index_ok');
} catch (PDOException $e) {
    Log::set('outcome', 'index_db_error');
    Log::set('db_error', $e->getMessage());
}

page_top('Lab Parts Store');
echo '<p>' . count($rows) . ' products in stock.</p>';
echo '<table><tr><th>Name</th><th>Category</th><th>Price</th></tr>';
foreach ($rows as $r) {
    echo '<tr><td><a href="/product.php?id=' . (int)$r['id'] . '">'
       . h((string)$r['name']) . '</a></td>'
       . '<td>' . h((string)$r['category']) . '</td>'
       . '<td>' . money((int)$r['price_cents']) . '</td></tr>';
}
echo '</table>';
page_end();
