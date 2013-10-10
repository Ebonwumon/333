<?php

require_once('hash_libv2.php');

$originalBytes = array();
$keyBytes = array();
$KEY_LENGTH = 33;

if (isset($_GET['maxChars'])) {
    $maxChars = $_GET['maxChars'];
} else {
    $maxChars = false;
}
getHashArrayFromFile("ciphertext2", $originalBytes, 0, $maxChars);
getKeySpace($keyBytes, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890~`!@#$%^&*()-_+=|[]{};:,.<>/?\\\"\'");

if (isset($_GET['text']) && isset($_GET['position'])) {
    $decrypted_bytes = array();
    $i = 0;
    $key = decodeKey(new HashByte(ord($_GET['text'])), $originalBytes[$_GET['position']], $map);
    $decrypted = assertKeyCharacter($key, $_GET['position'], $KEY_LENGTH, $originalBytes, $map);
    print json_encode(array("key" => chr($key->getASCII()),
                            "position" => $_GET['position'],
                             "decryption" => $decrypted));
    return;
}


/*
$possible_characters = array();

foreach ($keyBytes as $key) {
    $result = assertKeyCharacter($key, 1, $KEY_LENGTH, $originalBytes, $map);
    if ($result !== FALSE) $possible_characters[0][] = chr($result->getASCII());
}


/*for ($i = 0; $i < $KEY_LENGTH; $i++) {
    foreach ($keyBytes as $key) {
        $result = assertKeyCharacter($key, $i, $KEY_LENGTH, $newBytes, $map);
        if ($result !== FALSE) $possible_characters[$i][] = chr($result->getASCII());
    }
}

print_r($possible_characters);

//$potential_keys = getAllKeys($possible_characters);

print_r($potential_keys);
*/