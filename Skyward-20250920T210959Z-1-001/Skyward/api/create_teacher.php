<?php
<?php
header('Content-Type: application/json; charset=utf-8');

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

// Read DB credentials from environment (do NOT commit secrets)
$dbHost = getenv('DB_HOST') ?: '';
$dbName = getenv('DB_NAME') ?: '';
$dbUser = getenv('DB_USER') ?: '';
$dbPass = getenv('DB_PASS') ?: '';

if (!$dbHost || !$dbName || !$dbUser) {
    http_response_code(503);
    error_log('Missing DB environment configuration');
    echo json_encode(['success' => false, 'message' => 'Service unavailable']);
    exit;
}

$name = trim($_POST['teacher_name'] ?? '');
$email = trim($_POST['teacher_email'] ?? '');
$username = trim($_POST['teacher_username'] ?? '');
$password = $_POST['teacher_password'] ?? '';

if (!$name || !$email || !$username || !$password) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Missing required fields']);
    exit;
}

// Basic validations
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid email']);
    exit;
}
if (!preg_match('/^[a-zA-Z0-9_.-]{3,50}$/', $username)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid username (3-50 chars: letters, numbers, _, -, .)']);
    exit;
}
if (strlen($password) < 8) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Password must be at least 8 characters']);
    exit;
}

try {
    $dsn = "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4";
    $pdo = new PDO($dsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    // Check existing user
    $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1');
    $stmt->execute([$username, $email]);
    if ($stmt->fetch()) {
        http_response_code(409);
        echo json_encode(['success' => false, 'message' => 'Username or email already in use']);
        exit;
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare('INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([$name, $email, $username, $hash, 'teacher']);

    echo json_encode(['success' => true, 'message' => 'Teacher created']);
    exit;
} catch (Exception $e) {
    error_log('create_teacher error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server error']);


}    exit;    exit;
}