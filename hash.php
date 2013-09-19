<?php
$map = array(
array(0x7, 0x5, 0x0, 0x4, 0x2, 0x3, 0xb, 0x6, 0xa, 0x8, 0x9, 0xd, 0xc, 0xf, 0xe, 0x1),
array(0x3, 0x8, 0xd, 0xa, 0xc, 0xe, 0xf, 0xb, 0x7, 0x6, 0x4, 0x5, 0x1, 0x2, 0x0, 0x9),
array(0x4, 0x0, 0x3, 0x1, 0xb, 0xa, 0x8, 0x5, 0x9, 0xd,0xc, 0xe, 0xf, 0x6, 0x7, 0x2),
array(0x9, 0xe, 0x7, 0xc, 0x6, 0x4, 0x5, 0xd, 0x1, 0x0, 0x2, 0x3, 0xb, 0x8, 0xa, 0xf),
array(0x1, 0x3, 0xa, 0x2, 0x8, 0x9, 0xd, 0x0, 0xc, 0xe, 0xf, 0x7, 0x6, 0x5, 0x4, 0xb),
array(0xe, 0x6, 0x5, 0x7, 0x1, 0x0, 0x2, 0xf, 0x3, 0xb, 0xa, 0x8,0x9, 0xc, 0xd, 0x4),
array(0x2, 0xa, 0x9, 0xb, 0xd, 0xc, 0xe, 0x3, 0xf, 0x7, 0x6, 0x4, 0x5, 0x0, 0x1, 0x8),
array(0x6, 0x1, 0x2, 0x5, 0x3, 0xb, 0xa, 0x4, 0x8, 0x9, 0xd, 0xc, 0xe, 0x7, 0xf, 0x0),
array(0xb, 0x9, 0xc, 0x8, 0xe, 0xf, 0x7, 0xa, 0x6, 0x4, 0x5, 0x1, 0x0, 0x3,0x2, 0xd),
array(0x0, 0xb, 0x8, 0x3, 0x9, 0xd, 0xc, 0x2, 0xe, 0xf, 0x7, 0x6, 0x4, 0x1, 0x5, 0xa),
array(0x8, 0xc, 0xf, 0xd, 0x7, 0x6, 0x4, 0x9, 0x5, 0x1, 0x0, 0x2, 0x3, 0xa, 0xb, 0xe),
array(0x5, 0x2, 0xb, 0x0, 0xa, 0x8, 0x9, 0x1, 0xd, 0xc, 0xe, 0xf, 0x7, 0x4, 0x6, 0x3),
array(0xd, 0xf, 0x6, 0xe, 0x4, 0x5, 0x1, 0xc, 0x0, 0x2, 0x3, 0xb, 0xa, 0x9, 0x8, 0x7),
array(0xc, 0x7, 0x4, 0xf, 0x5, 0x1, 0x0, 0xe, 0x2, 0x3, 0xb, 0xa, 0x8, 0xd, 0x9, 0x6),
array(0xa, 0xd, 0xe, 0x9, 0xf, 0x7, 0x6, 0x8, 0x4, 0x5, 0x1, 0x0, 0x2, 0xb, 0x3, 0xc),
array(0xf, 0x4, 0x1, 0x6, 0x0, 0x2, 0x3, 0x7, 0xb, 0xa, 0x8, 0x9, 0xd, 0xe, 0xc, 0x5));

$file = fopen("ciphertext1", "r");

// Nibbles of key characters
$keylower = array();
$keyupper = array();
$originalBytes = array();
$i = 0;

while (!feof($file)) {
	$raw_byte = fread($file, 1); 
        //Converting it to a binary string, adding 0 to left if not 8 bits
	$byte = str_pad(decbin(ord($raw_byte)), 8, "0", STR_PAD_LEFT);
        $originalBytes[] = $byte;
	$bit1 = substr($byte, 0, 4); //Breaks byte into halves
        $bit2 = substr($byte, 4, 4);
        //Searches for column index of each key nibble and puts it into an array
	foreach ($map as $col) {
		$ind = array_search(bindec($bit1), $col);
		$keylower[$i][]=$ind; 	
		$ind = array_search(bindec($bit2), $col);
		$keyupper[$i][]=$ind;	
	}
	$i++;
	
}

//All possible ASCII characters
$patterns = array();

for ($j = 0; $j < count($keylower); $j++) {
    for($k = 0; $k < 16; $k++) {
        //Takes binary representation of keyupper/keylower and pads with zeros (4 bit nibble)
        $keyupperbin = str_pad(decbin($keyupper[$j][$k]), 4, "0", STR_PAD_LEFT);
	for ($l = 0; $l < 16; $l++) {
            $keylowerbin = str_pad(decbin($keylower[$j][$l]), 4, "0", STR_PAD_LEFT);
            //Adds halves together to make an ASCII character (1byte)
            $ascii = bindec($keyupperbin . $keylowerbin);
            if (($ascii > 47 && $ascii < 58) || ($ascii > 64 && $ascii < 91) || ($ascii > 96 && $ascii < 123)) {
                $patterns[$j][] = $ascii;
            }
        }
    }
}

print_r(determinePotentialKeyCharactersForByte($patterns[0], $originalBytes[0], $map));
die();

/**
	takes: $keyChar = decimal value of the ascii key value
	$originalByte = 8-bit binary representation of the original encrypted byte
	$hashMap = The hashing algorithm map

	returns: the decimal value of the decoded byte 
*/
function decodeByte($keyChar, $originalByte, $hashMap) {
	$key_in_binary = str_pad(decbin($keyChar), 8, "0", STR_PAD_LEFT);
	$keyupper_binary = substr($key_in_binary, 0, 4);
	$keylower_binary = substr($key_in_binary, 4, 4);
	$originalByte_upper = substr($originalByte, 0, 4);
	$originalByte_lower = substr($originalByte, 4, 4);
	$i = 0;
	foreach ($hashMap as $col) {
		if ($col[bindec($keylower_binary)] == bindec($originalByte_upper)) {
			$decrypted_upper_dec = $i;
		}
		if ($col[bindec($keyupper_binary)] == bindec($originalByte_lower)) {
			$decrypted_lower_dec = $i;
		}
		$i++;
	}
	$decrypted_upper_bin = str_pad(decbin($decrypted_upper_dec), 4, "0", STR_PAD_LEFT);
	$decrypted_lower_bin = str_pad(decbin($decrypted_lower_dec), 4, "0", STR_PAD_LEFT);
	$decrypted = bindec($decrypted_upper_bin . $decrypted_lower_bin);
	return $decrypted; 	
}


/**
	Takes: 
*/
function determinePotentialKeyCharactersForByte($keys, $originalByte, $hashMap) {
	$printable_keys = array();
	foreach ($keys as $key) {
		$print = isPrintable(decodeByte($key, $originalByte, $hashMap));
		if ($print !== FALSE) {
			$printable_keys[] = $print;
		}
	}
	return $printable_keys;	
}

// Used for computing potential key lengths
/*$success = array();
for ($j = 1; $j < 444; $j++) {
	$bool = computeApproved($patterns, $j);
	if ($bool) {
		$success[] = $j;
	}
}
print_r($success);

die();*/


$key = array('length' => 36, 'assert' => array('key' => '0', 'value' => str_pad(decbin($working_potential_keys[0][8]), 8, "0", STR_PAD_LEFT)));

print(assertKey($originalBytes, $map, $key));


/** Takes:
	$sourceText: array of 8-bit encrypted source characters (padded with 0's to the left)
	$hashMap: the mapping of the encryption scheme
	$key: [ 'length' => of key,
		'assert' => [ 'key' => position of char in key, 'value' => binary string of the ascii key ]
		]
*/
function assertKey($sourceText, $hashmap, $key) {
	$result = "";
	$i = 0;
	foreach ($sourceText as $s) {
		if ($i == $key['assert']['key']) {
			$higherSource = substr($s, 0, 4);
			$lowerSource = substr($s, 4, 4);
			$higherKey = substr($key['assert']['value'], 0, 4);
			$lowerKey = substr($key['assert']['value'], 4, 4);
			$higherPlain = 0;
			$lowerPlain = 0;
			
			for ($j = 0; $j < count($hashmap); $j++) {
				if ($hashmap[$j][bindec($higherKey)] == bindec($lowerSource)) {
					$lowerPlain = $j;
				}
				if ($hashmap[$j][bindec($lowerKey)] == bindec($higherSource)) {
					$higherPlain = $j;
				}	
			}
			$bin = str_pad(decbin($higherPlain), 4, "0", STR_PAD_LEFT) . str_pad(decbin($lowerPlain), 4, "0",STR_PAD_LEFT);
			$result .= "<" .chr(bindec($bin)) . ">";
		} else {
			$result .= ".";
		}
		if ($i == $key['length'] -1) {
			$i = 0;
		} else {
			$i++;
		}
	}
	return $result;
}

function computeRepeatedKeys($pattern_array, $KEY_LENGTH) {
	$count = 0;
	$approvedkeys = array();
	for ($j = 0; $j < $KEY_LENGTH; $j++) {
		$approvedkeys[] = $pattern_array[$j];
	}
	$approvedkeysiterable = $approvedkeys;
	for ($j = $KEY_LENGTH; $j < count($pattern_array); $j++) {
		foreach ($approvedkeysiterable[$j % $KEY_LENGTH] as $key => $value) {
			if (array_search($value, $pattern_array[$j]) === FALSE) {
				$removeKey = array_search($value, $approvedkeys[$j % $KEY_LENGTH]);
				if ($removeKey !== FALSE) {
					//print($j .  ": " . $approvedkeys[$j % 9][$removeKey] . " removed from " . $j % 9 . "\n"); 
					unset($approvedkeys[$j % $KEY_LENGTH][$removeKey]);
				}
			}
		}
	}

	foreach ($approvedkeys as $arr) {
		if (count($arr) == 0) {
			return false;
		}
	}
	return $approvedkeys;
}

/** Takes int and compute if int is within displayable ASCII. 
 * If true, returns what was given
 * If false, returns FALSE */
function isPrintable($asciiNum) {
    if ($asciiNum > 31 && $asciiNum < 127) {
        return($asciiNum);
    }
    else {
        return(FALSE);
    }
}

fclose($file);
?>
