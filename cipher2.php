<?php

require_once('lib.php');

$originalBytes = array();
$keyBytes = array();
$KEY_LENGTH = 33;
$maxChars = 500; // We're just going to work with the first 500 characters of the text

getHashArrayFromFile("ciphertext2", $originalBytes, 0, $maxChars);
getKeySpace($keyBytes, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890~`!@#$%^&*()-_+=|[]{};:,.<>/?\\\"\'");

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

$fullFile = array();
print("\nOkay, let's decrypt using the key: " . $key_text);
getHashArrayFromFile("ciphertext2", $fullFile);
file_put_contents("decrypted.pdf", decryptWithKey($key_text, $fullFile, $map));
print("DONE!");


