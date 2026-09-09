<?php
require __DIR__ . '/bootstrap.php';

$productId = (int)($_POST['product_id'] ?? 0);
$author    = trim((string)($_POST['author'] ?? ''));
$body      = (string)($_POST['body'] ?? '');

if ($author === '') {
    $author = 'anonymous';
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || $productId <= 0 || $body === '') {
    Log::set('outcome', 'comment_rejected');
    http_response_code(400);
    page_top('Comment rejected');
    echo '<p class="err">Missing product or empty comment.</p>';
    page_end();
    return;
}

try {
    // VULNERABILITY: the comment body is stored verbatim, with no encoding and
    // no allow-list of markup. CWE-79, storage half; the sink is product.php.
    // The statement itself IS parameterised, so this is not SQL injection.
    // Storing raw input is defensible only if every consumer encodes on output,
    // and product.php does not.
    // FIX: encode on output in product.php. If you genuinely must store markup,
    // run it through a real HTML sanitiser here, not a regex.
    $st = db()->prepare('INSERT INTO comments (product_id, author, body) VALUES (?, ?, ?)');
    $st->execute([$productId, $author, $body]);
    Log::set('outcome', 'comment_stored');
} catch (PDOException $e) {
    Log::set('outcome', 'comment_db_error');
    Log::set('db_error', $e->getMessage());
}

header('Location: /product.php?id=' . $productId);
