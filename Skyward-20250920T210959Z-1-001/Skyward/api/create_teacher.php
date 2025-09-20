<?php
<?php
header('Content-Type: application/json; charset=utf-8');

try {
    $pdo = new PDO('mysql:host=localhost;dbname=skyward;charset=utf8mb4', 'dbuser', 'dbpass', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);

    $name = trim($_POST['teacher_name'] ?? '');
    $email = trim($_POST['teacher_email'] ?? '');
    $username = trim($_POST['teacher_username'] ?? '');
    $password = $_POST['teacher_password'] ?? '';

    if (!$name || !$email || !$username || !$password) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing required fields']);
        exit;
    }

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
} catch (Exception $e) {
    error_log($e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server error']);
}