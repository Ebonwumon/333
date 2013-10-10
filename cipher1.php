<?php

require_once('hash_lib.php');

$originalBytes = array();
$keyBytes = array();
$KEY_LENGTH = 8;
$keyspace = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\n\0";


getHashArrayFromFile("ciphertext1", $originalBytes, $keyBytes, $map);
getKeySpace($keyBytes, $keyspace);

$possible_characters = array();
for ($i = 0; $i < $KEY_LENGTH; $i++) {
    foreach ($keyBytes as $key) {
        $result = assertKeyCharacter($key, $i, $KEY_LENGTH, $originalBytes, $map);
        if ($result !== FALSE) $possible_characters[$i][] = chr($result->getASCII());
    }
}

$potential_keys = getAllKeys($possible_characters);


// User intervention if we have multiple keys
if (count($potential_keys) > 1 ) {
    $key_ind = "";
    while($key_ind != "q") {
        print("Choose a key to try [q to quit]: \n");
        $i = 0;
        foreach ($potential_keys as $key) {
            print ("[" . $i . "] " . $key . "\n");
            $i++;
        }
        $key_ind = trim(fgets(STDIN));
        if ($key_ind == "q") break;
        $decryption_candidate = decryptWithKey($potential_keys[$key_ind], $originalBytes, $map);
        print($decryption_candidate);
    }
} else {
    //only one key logic
}
