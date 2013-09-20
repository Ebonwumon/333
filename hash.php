<?php

// all our helper functions and mapping is in the lib
require_once('hash_lib.php');

$file = fopen("ciphertext1", "r");

// Nibbles of key characters
$keyBytes = array();
$originalBytes = array();
$i = 0;

while (!feof($file)) {
	$raw_byte = fread($file, 1); 
        //Converting it to a binary string, adding 0 to left if not 8 bits
	$byte = new HashByte(ord($raw_byte));
        $originalBytes[] = $byte;
	//Searches for column index of each key nibble and puts it into an array
	foreach ($map as $col) {
		$indUp = array_search(bindec($byte->getUpper()), $col);
		$indLow = array_search(bindec($byte->getLower()), $col);
		$keyBytes[$i][] = HashByte::fromTwoDecimals($indUp, $indLow);
	}
	$i++;
}

//All possible ASCII characters
$alphanumeric_keys = array();

$l = 0;
foreach ($keyBytes as $keys) {
	for ($j = 0; $j < count($keys); $j++) {
		for ($k = 0; $k < count($keys); $k++) {
			$hashByte = new HashByte($keys[$j]->getUpper() . $keys[$k]->getLower());
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
for($j = 0; $j < count($alphanumeric_keys); $j++) {	
	$possible_characters[] = determinePotentialKeyCharactersForByte($alphanumeric_keys[$j], $originalBytes[$j], $map); 
}

print_r($possible_characters);

fclose($file);
