<?php

require_once('libv2.php');

$originalBytes = array();
$keyBytes = array();
$KEY_LENGTH = 33; // Key length is determined before the running of the program, and inputted here.
$maxChars = 500; // We're just going to work with the first 500 characters of the text

print("Beginning decryption...\n");

getHashArrayFromFile("ciphertext2", $originalBytes, $maxChars);

// We want all printable characters and symbols included in our potential keyspace
getKeySpace($keyBytes, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890~`!@#$%^&*()-_+=|[]{};:,.<>/?\\\"\'");

/**
 * Block of code that attempts to decode each byte of the provided ciphertext with every possible key.
 * It will count the attempts at decoding and how many of those yielded printable ASCII.
 * Those with the top success rate at decoding to printable ASCII are saved for human intervention.
 *
 * ASSUMPTIONS HERE: The file will have metadata before a binary blob. We are assuming this binary data occurs roughly
 * in the first 500 bytes of the cipher file.
 */
$possible_characters = array();
for ($i = 0; $i < $KEY_LENGTH; $i++) {
    $best_success = array();
    foreach ($keyBytes as $key) {
        $result = assertKeyCharacter($key, $i, $KEY_LENGTH, $originalBytes, $map);
        if ($result !== FALSE) {
            $best_success[$result['success']][] = $result['key'];
        }
    }
    ksort($best_success);
    $best_success = array_reverse($best_success);
    $possible_characters[$i] = array_shift($best_success);
}

/**
 * This block of code handles human intervention. We assume the key is a readable string of characters that will have
 * meaning. Therefore, if we display to a human all the options for the next 5 characters of the key, they should be
 * able to put together a string that has meaning.
 */
$key_text = "";
$i = 0;
while (strlen($key_text) < 33) {
    print("Choose the next character in the key:\n");
    for ($j = $i; $j < 33 && $j < ($i + 5); $j++) {
        print("[" . $j . "] ");
        if ($j == 29) {
            print("{ _ }");
        } else {
        foreach ($possible_characters[$j] as $char) {
            print ("{ " . $char . " } ");
        }
        }
    }
    print("\nKey: " . $key_text);
    $char = fgets(STDIN);
    $char = substr($char, 0, 1);
    $key_text .= $char;
    $i++;

}
print("\nOkay, let's decrypt using the key: " . $key_text);

/**
 * Once we have the key text thanks to our ever smart NSA-Analyst-Human, we need to load into RAM the entire Ciphertext,
 * and just go ham on it, decoding with the key.
 */
$fullFile = array();
getHashArrayFromFile("ciphertext2", $fullFile);
file_put_contents("decrypted.pdf", decryptWithKey($key_text, $fullFile, $map));
print("\nDONE!");


