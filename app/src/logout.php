<?php
require __DIR__ . '/bootstrap.php';

$_SESSION = [];
session_destroy();
Log::set('outcome', 'logout_ok');
header('Location: /index.php');
