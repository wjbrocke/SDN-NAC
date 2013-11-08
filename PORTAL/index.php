<html>
Welcome to the captive portal!

<?php
$redirect = urlencode("http://{$_SERVER['SERVER_NAME']}{$_SERVER['REQUEST_URI']}");

print("To sign onto the network please <a href=\"/nac/index.php?redirect=$redirect\">authenticate</a>.");
?>
</html>
