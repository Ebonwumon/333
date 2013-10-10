<?php

require_once('hash_lib.php');

$originalBytes = array();
$keyBytes = array();
$KEY_LENGTH = 8; // Key length is predetermined by a separate program
// Our keyspace is only alphanumeric
$keyspace = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\n\0";


getHashArrayFromFile("ciphertext1", $originalBytes);
getKeySpace($keyBytes, $keyspace);

/**
 * ASSUMPTION: the plaintext is entirely human-readable ASCII. Therefore if any key doesn't decode a character into
 * printable ASCII every mod_key_length_nth byte, it is not a usable key and we can throw it out
 */
$possible_characters = array();
for ($i = 0; $i < $KEY_LENGTH; $i++) {
    foreach ($keyBytes as $key) {
        $result = assertKeyCharacter($key, $i, $KEY_LENGTH, $originalBytes, $map);
        if ($result !== FALSE) $possible_characters[$i][] = chr($result->getASCII());
    }
}

// We compile our list of options for each key character into a list of possible keys
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
    //only one key logic - I left this unimplemented because I knew it was not the case and would be wasted effort
}
