<?php

require_once("../lib.php");

$mac = getMAC($_SERVER['REMOTE_ADDR']);

$result = permitClient($_SERVER['PHP_AUTH_USER'],$mac,$_SERVER['REMOTE_ADDR']);

$redirect = $_GET['redirect'];
if(preg_match("/<value><nil\/><\/value>/",$result)){
    print "<html>\n";
    print "<head>\n";
    print "<meta http-equiv=\"refresh\" content=\"5; url=$redirect\"/>\n";
    print "</head>\n";
    print "<body>\n";
    print "You will be redirected to your original URL in 5 seconds: <a href=\"$redirect\">$redirect</a>.<br/>\n";
    print "</body>\n";
    print "</html>\n";
} else {
    print "An error occured... please contact your network administrator.";
}
?>
