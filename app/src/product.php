<?php
require __DIR__ . '/bootstrap.php';

$id       = (int)($_GET['id'] ?? 0);
$product  = null;
$comments = [];

try {
    // Parameterised on purpose. The defect on this page is output encoding,
    // not the lookup.
    $st = db()->prepare(
        'SELECT id, name, category, price_cents, spec_file FROM products WHERE id = ?'
    );
    $st->execute([$id]);
    $product = $st->fetch() ?: null;

    if ($product !== null) {
        $cs = db()->prepare(
            'SELECT author, body, created_at FROM comments WHERE product_id = ? ORDER BY id'
        );
        $cs->execute([$id]);
        $comments = $cs->fetchAll();
        Log::set('outcome', 'product_ok');
    } else {
        Log::set('outcome', 'product_not_found');
    }
} catch (PDOException $e) {
    Log::set('outcome', 'product_db_error');
    Log::set('db_error', $e->getMessage());
}

page_top($product !== null ? (string)$product['name'] : 'Product not found');

if ($product === null) {
    echo '<p class="err">No such product.</p>';
    page_end();
    return;
}

echo '<p>' . h((string)$product['category']) . ' &middot; '
   . money((int)$product['price_cents']) . '</p>';

if (!empty($product['spec_file'])) {
    echo '<p><a href="/download.php?file=' . urlencode((string)$product['spec_file'])
       . '">Download spec sheet</a></p>';
}

echo '<h2>Comments</h2>';
foreach ($comments as $c) {
    // VULNERABILITY: stored cross-site scripting. CWE-79. The comment body is
    // written into the page exactly as submitted, so a payload saved once
    // executes in every later visitor's browser, in this site's origin, with
    // access to the session cookie.
    //   Try:  <script>alert(document.cookie)</script>
    //         <img src=x onerror=alert(1)>
    // FIX: echo h((string)$c['body']);
    // Note the author field on the same line IS escaped. That contrast is the
    // thing to point at when someone asks you to explain output encoding.
    echo '<div class="c"><b>' . h((string)$c['author']) . '</b> '
       . '<small>' . h((string)$c['created_at']) . '</small><br>'
       . $c['body']
       . '</div>';
}

// VULNERABILITY (secondary, no code needed to demo it): this form carries no
// CSRF token. CWE-352. Any third-party page can make a logged-in visitor's
// browser POST a comment as them.
// FIX: issue a per-session token, include it as a hidden field, and compare it
// with hash_equals() before accepting the write.
echo '<form method="post" action="/comment.php">'
   . '<input type="hidden" name="product_id" value="' . (int)$product['id'] . '">'
   . '<p>Name <input name="author"></p>'
   . '<p>Comment<br><textarea name="body" rows="3" cols="60"></textarea></p>'
   . '<p><button>Post comment</button></p></form>';

page_end();
