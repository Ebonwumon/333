<?php

// all our helper functions and mapping is in the lib
require_once('hash_lib.php');


// Nibbles of key characters
$keyBytes = array();
$i = 0;
$KEY_LENGTH = 8;
$originalBytes = array();
$keyBytes = array();

getHashArrayFromFile("ciphertext1", $originalBytes, $keyBytes, $map);

//All possible ASCII characters
$alphanumeric_keys = array();

$l = 0;
foreach ($keyBytes as $keys) {
	for ($j = 0; $j < count($keys); $j++) {
		for ($k = 0; $k < count($keys); $k++) {
			$hashByte = new HashByte(bindec($keys[$j]->getUpper() . $keys[$k]->getLower()));
			$ascii = $hashByte->getASCII();
			if (($ascii > 47 && $ascii < 58) || ($ascii > 64 && $ascii < 91) || 
			    ($ascii > 96 && $ascii < 123)) {
                		$alphanumeric_keys[$l][] = $hashByte;
            		}
		}
	}
$l++;
}


$possible_characters = array();
for ($i = 0; $i < $KEY_LENGTH; $i++) {
    foreach ($alphanumeric_keys[$i] as $key) {
        $result = assertKeyCharacter($key, $i, $KEY_LENGTH, $originalBytes, $map);
        if ($result !== FALSE) $possible_characters[$i][] = chr($result->getASCII());
    }
}

$potential_keys = getAllKeys($possible_characters);

if (count($potential_keys) > 1 ) {
    print("Choose a key to try: \n");
    $i = 0;
    foreach ($potential_keys as $key) {
        print ("[" . $i . "] " . $key);
        $i++;
    }
    $key_ind = trim(fgets(STDIN));
    $decryption_candidate = decryptWithKey("2brodsky", $originalBytes, $map);
    print($decryption_candidate);
}

/*$possible_characters = $alphanumeric_keys;
//$possible_characters = array();

/*for($j = 0; $j < count($alphanumeric_keys); $j++) {	
	$dec = determinePotentialKeyCharactersForByte($alphanumeric_keys[$j], $originalBytes[$j], $map); 
	$possible_characters[] = $dec;
	//$possible_characters[] = new HashByte($dec);
}

// Used for computing potential key lengths
print_r($possible_characters[0]);
die();
$repeated_keys = computeRepeatedKeys($possible_characters, 8);
if ($repeated_keys === FALSE) {
	print ("Keys do not repeat \n");
	die();
}
print_r($repeated_keys);
die();

$i = 0;
$decryptable_key = array();
foreach ($possible_characters[0] as $key) {
	print_r($key);
	if (assertKeyCharacter($key, 8, $originalBytes, $map)) {
		$decryptable_key[$i][] = new HashByte($key); 	
	}
	$i++;
	
}

print_r($decryptable_key);

die();

for ($j = 1; $j < 444; $j++) {
	$bool = computeRepeatedKeys($possible_characters, $j);
	if ($bool) {
		$success[] = $j;
	}
	if ($j == 20 ) { die(); }
}
print_r($success); */




