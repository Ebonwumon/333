<?php

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


/**
	takes: $key = A HashByte of the current Key character 
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


function assertKeyCharacter($key, $key_position, $key_length, $originalBytes, $map) {
	for ($i = 0; $i < count($originalBytes); $i++) {
		if ($i % $key_length != $key_position) continue;
		$decoded = decodeByte($key, $originalBytes[$i], $map);
		if (isPrintable($decoded) !== FALSE) continue;
		else return false;
	}

	return $key;
}

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
    $repeated_keys = array();

	$approved_keys = array();
	for ($j = 0; $j < $KEY_LENGTH; $j++) {
		$approved_keys[] = $pattern_array[$j];
	}

	$approvedkeysiterable = $approved_keys;
	for ($j = $KEY_LENGTH; $j < count($pattern_array); $j++) {
		foreach ($approvedkeysiterable[$j % $KEY_LENGTH] as $value) {
			if (array_search($value, $pattern_array[$j]) === FALSE) {
				$removeKey = array_search($value, $approved_keys[$j % $KEY_LENGTH]);
				if ($removeKey !== FALSE) {
					unset($approved_keys[$j % $KEY_LENGTH][$removeKey]);
				}
			}
		}
	}

	foreach ($approved_keys as $arr) {
		if (count($arr) == 0) {
			return false;
		}
	}
	return $approved_keys;
}

/** Takes int and compute if int is within displayable ASCII. 
 * If true, returns what was given
 * If false, returns FALSE */
function isPrintable($asciiNum) {
    if (($asciiNum > 31 && $asciiNum < 127) || $asciiNum == 9 || $asciiNum == 10 || $asciiNum == 13) {
 	   return($asciiNum);
    }
    else {
        return(FALSE);
    }
}

