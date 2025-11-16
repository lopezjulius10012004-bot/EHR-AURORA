<?php
session_start();
if (isset($_SESSION['admin'])) {
    $_SESSION['last_activity'] = time();
}
echo 'OK';
?>
