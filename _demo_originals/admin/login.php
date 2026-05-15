<?php
/**
 * TechSolutions Lanka - Admin Login Portal
 * Internal use only
 */
session_start();
require_once '../config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = htmlspecialchars($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    // NOTE: In production this checks against the database
    if ($username === 'admin' && password_verify($password, ADMIN_HASH)) {
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_user']      = $username;
        header('Location: dashboard.php');
        exit;
    } else {
        $error = 'Invalid credentials.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Login - TechSolutions Lanka</title>
</head>
<body>
    <h1>Admin Portal</h1>
    <?php if (!empty($error)) echo "<p style='color:red'>$error</p>"; ?>
    <form method="POST">
        <label>Username: <input type="text" name="username" required></label><br>
        <label>Password: <input type="password" name="password" required></label><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
