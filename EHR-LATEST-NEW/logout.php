<?php
session_start();
include "db.php";

// Clear the session_id in the database for the logged-in admin
if (isset($_SESSION['admin_id'])) {
    $stmt = $conn->prepare("UPDATE admin SET session_id = NULL WHERE id = ?");
    $stmt->bind_param("i", $_SESSION['admin_id']);
    $stmt->execute();
    $stmt->close();
}

// Log timeout if this is a timeout logout
if (isset($_GET['timeout']) && $_GET['timeout'] == '1') {
    // Optional: Log timeout event to audit trail or file
    error_log("Session timeout logout for admin: " . ($_SESSION['admin'] ?? 'unknown'));
}

session_unset();
session_destroy();
header("Location: index.php");
exit();
?>
