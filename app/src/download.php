<?php
require __DIR__ . '/bootstrap.php';

$file = (string)($_GET['file'] ?? '');

if ($file === '') {
    Log::set('outcome', 'download_denied');
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "No file requested.\n";
    return;
}

// VULNERABILITY: path traversal. CWE-22. The supplied name is joined onto the
// base directory with no normalization and no containment check, so ../
// sequences walk out of specs/ and reach anything readable by the Apache
// worker.
//   Try:  ?file=../../../../etc/passwd
//         ?file=../html/bootstrap.php     (leaks the database credentials)
// FIX:
//   $root = realpath(SPECS_DIR);
//   $real = realpath(SPECS_DIR . $file);
//   if ($real === false || !str_starts_with($real, $root . DIRECTORY_SEPARATOR)) { deny; }
// realpath() resolves .., symlinks and duplicate slashes BEFORE the check,
// which is why the prefix comparison must run on the resolved path. Stripping
// "../" from the raw string is not a fix; "....//" defeats it.
$path = SPECS_DIR . $file;

if (!is_file($path) || !is_readable($path)) {
    Log::set('outcome', 'download_denied');
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Not found.\n";
    return;
}

Log::set('outcome', 'download_ok');
header('Content-Type: text/plain; charset=utf-8');
header('Content-Disposition: inline; filename="' . basename($path) . '"');
readfile($path);
