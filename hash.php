<?php

// all our helper functions and mapping is in the lib
require_once('hash_lib.php');


// Nibbles of key characters
$keyBytes = array();
$originalBytes = array();
$i = 0;
$KEY_LENGTH = 8;

$file = fopen("ciphertext1", "r");
while (!feof($file)) {
	$raw_byte = fread($file, 1); 
        //Converting it to a binary string, adding 0 to left if not 8 bits
	$byte = new HashByte(ord($raw_byte));
        $originalBytes[] = $byte;
	//Searches for column index of each key nibble and puts it into an array
	foreach ($map as $col) {
		$indUp = array_search(bindec($byte->getUpper()), $col);
		$indLow = array_search(bindec($byte->getLower()), $col);
		$hashByte = HashByte::fromTwoDecimals($indUp, $indLow);
		$keyBytes[$i][] = $hashByte;		
	}
	$i++;
}
fclose($file);
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
        if ($result !== FALSE) {
            $possible_characters[$i][] = chr($result->getASCII());
        }
    }
}

print_r($possible_characters);

die();
/*
for($j = 0; $j < count($alphanumeric_keys); $j++) {
	$dec = determinePotentialKeyCharactersForByte($alphanumeric_keys[$j], $originalBytes[$j], $map); 
	$possible_characters[$j] = $dec;
	//$possible_characters[] = new HashByte($dec);
}

print_r($possible_characters);

// Used for computing potential key lengths
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
print_r($success); 
*/



