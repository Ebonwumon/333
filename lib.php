<?php

/*      Datatype to represnt a single byte.
        Functions for converting byte to string of binary representation,
        getting the upper and lower 4 bits of the byte, 
        and getting the ASCII representation. 
*/
class HashByte {
	
	public $byte;

	public function __construct($dec) {
		$this->byte = str_pad(decbin($dec), 8, "0", STR_PAD_LEFT);
	}

	public function getUpper() {
		return substr($this->byte, 0, 4);
	}

	public function getLower() {
		return substr($this->byte, 4, 4);
	}
	
	public function getByte() {
		return $this->byte;
	}

	public function getASCII() {
		return bindec($this->byte);
	}
	
	static function fromTwoDecimals($high, $low) {
		$high = str_pad(decbin($high), 4, "0", STR_PAD_LEFT);
		$low = str_pad(decbin($low), 4, "0", STR_PAD_LEFT);
		return new HashByte(bindec($high . $low));
	}
}

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


function getHashArrayFromFile($filename, &$originalBytes, $i = 0, $MAX = false) {
    $file = fopen($filename, "r");
    while (!feof($file)) {
        if ($MAX && (int)$MAX <= $i) {
            break;
        }
        $raw_byte = fread($file, 1);
        if (feof($file)) break;
        //Converting it to a binary string, adding 0 to left if not 8 bits
        $byte = new HashByte(ord($raw_byte));
        $originalBytes[] = $byte;
        //Searches for column index of each key nibble and puts it into an array
        $i++;
    }
    fclose($file);
    return $originalBytes;
}

function getKeySpace(&$keyBytes, $allowed_chars) {
    foreach (str_split($allowed_chars) as $char) {
        $keyBytes[] = new HashByte(ord($char));
    }

    return $keyBytes;
}

/**
	Takes:
        $key = A HashByte of the current Key character 
	$originalByte = A HashByte of the original cryptographic hash byte.
	$hashMap = The hashing algorithm map

	returns: the decimal value of the decoded byte 
*/
function decodeByte($key, $originalByte, $hashMap) {
	$i = 0;
	foreach ($hashMap as $col) {
		if ($col[bindec($key->getLower())] == bindec($originalByte->getUpper())) {
			$decrypted_upper_dec = $i;
		}
		if ($col[bindec($key->getUpper())] == bindec($originalByte->getLower())) {
			$decrypted_lower_dec = $i;
		}
		$i++;
	}
	$decryptedHashByte = HashByte::fromTwoDecimals($decrypted_upper_dec, $decrypted_lower_dec);
	return $decryptedHashByte->getASCII(); 	
}

/**
	Takes: 
        $keys = All the alphanumeric keys
        $originalByte = Current byte from ciphertext
        $hashMap = The hashing algorithm map

        Takes all possible alphanumeric keys (62 total) and checks if decrypting current
        byte with each key results in printable ASCII. Printable keys are saved in an array.
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

/**
        Takes:
        $key = Key being tested 
        $length = Assumed key length
        $originalBytes = All bytes in cihpertext file
        $map = Encryption map

        Checks if every byte decoded with predicted key is printable ASCII.
*/
function assertKeyCharacter($key, $key_position, $key_length, $originalBytes, $map) {

    $i = $key_position;
    $successful_decryptions = 0;
    $total_attempts = 0;
    while ($i < count($originalBytes)) {
        $decoded = decodeByte($key, $originalBytes[$i], $map);

        if (isPrintable($decoded) !== FALSE) {
            $successful_decryptions++;
        }
        $total_attempts++;
        $i += $key_length;
    }

    if ($total_attempts == 0) {
        $total_attempts = 1;
    }

    $success = ($successful_decryptions / $total_attempts) * 1000;
    if ($success < 0.8) {
        return false;
    }
    return [ 'success' => $success, 'key' => chr($key->getASCII()) ];

}


function getAllKeys($arrays)
{
    $result = array();
    $arrays = array_values($arrays);
    $sizeIn = sizeof($arrays);
    $size = $sizeIn > 0 ? 1 : 0;
    foreach ($arrays as $array)
        $size = $size * sizeof($array);
    for ($i = 0; $i < $size; $i ++)
    {
        $result[$i] = array();
        for ($j = 0; $j < $sizeIn; $j ++)
            array_push($result[$i], current($arrays[$j]));
        for ($j = ($sizeIn -1); $j >= 0; $j --)
        {
            if (next($arrays[$j]))
                break;
            elseif (isset ($arrays[$j]))
                reset($arrays[$j]);
        }
    }
    $strings = array();
    foreach ($result as $string) {
        $strings[] = implode($string);
    }
    return $strings;
}

function decryptWithKey($key, $originalBytes, $map) {
    $result = "";
    $KEY_LENGTH = strlen($key);
    $keyhash = array();
    foreach (str_split($key) as $chr) {
        $keyhash[] = new HashByte(ord($chr));
    }
    for ($i = 0; $i < count($originalBytes); $i++) {
        $result .= chr(decodeByte($keyhash[$i % $KEY_LENGTH], $originalBytes[$i], $map));
    }

    return $result;
}

/**     Takes:
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

/**
        Takes:
        $pattern_array = List of all possible keys for eac letter
        $KEY_LENGTH = Consant for key length
*/
function computeRepeatedKeys($pattern_array, $KEY_LENGTH) {
	$count = 0;
	$approvedkeys = array();
	for ($j = 0; $j < $KEY_LENGTH; $j++) {
		$approvedkeys[] = $pattern_array[$j];
	}
	$approvedkeysiterable = $approvedkeys;
	for ($j = $KEY_LENGTH; $j < count($pattern_array); $j++) {
		foreach ($approvedkeysiterable[$j % $KEY_LENGTH] as $value) {
			if (array_search($value, $pattern_array[$j]) === FALSE) {
				$removeKey = array_search($value, $approvedkeys[$j % $KEY_LENGTH]);
				if ($removeKey !== FALSE) {
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

/** 
        Takes an int and computes if the int is within displayable ASCII. 
        If true, returns int which was given.
        If false, returns FALSE 

function isPrintable($asciiNum) {
    if (($asciiNum > 31 && $asciiNum < 127) || $asciiNum == 9 || $asciiNum == 10 || $asciiNum == 13
        || $asciiNum == 253) {
 	   return($asciiNum);
    }
    else {
        return(FALSE);
    }
}*/

function isPrintable($asciiNum) {
    if (($asciiNum > 31 && $asciiNum < 127) || $asciiNum == 9 || $asciiNum == 10 || $asciiNum == 13) {
        return($asciiNum);
    }
    else {
        return(FALSE);
    }
}



