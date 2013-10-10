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

// Our vigenere ciper
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
 * @param $filename: name of the ciphertext file to decrypt. Should be in same directory as php script
 * @param $originalBytes: reference to array where we will store the HashBytes that we load from the file
 * @return array : returns the resulting bytes - it should have been automatically loaded into the referenced array
 *      anyway
 */
function getHashArrayFromFile($filename, &$originalBytes) {
    $file = fopen($filename, "r");
    while (!feof($file)) {
        $raw_byte = fread($file, 1);
        if (feof($file)) break;
        $byte = new HashByte(ord($raw_byte));
        $originalBytes[] = $byte;
    }
    fclose($file);
    return $originalBytes;
}

/**
 * @param $keyBytes : Reference to array that will contain hashbytes which are acceptable key values
 * @param $allowed_chars : String passed of all the acceptable characters in the key
 * @return array : returns the array of hashbytes
 */
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
 * @param $key : HashByte of the Key character to decrypt with
 * @param $key_position : Position of this key character in the key string.
 * @param $key_length : the length of our vigenere key for this cipher
 * @param $originalBytes : array of HashBytes representing the ciphertext
 * @param $map : the vigenere cipher map
 * @return returns the key if it successfully decrypts to printable ASCII every mod_key_length character in the
 *          cipher. returns false otherwise.
 */
function assertKeyCharacter($key, $key_position, $key_length, $originalBytes, $map) {
	for ($i = 0; $i < count($originalBytes); $i++) {
		if (($i % $key_length) != $key_position) { continue; }

		$decoded = decodeByte($key, $originalBytes[$i], $map);

		if (isPrintable($decoded) !== FALSE) {
            continue;
        }
		else return false;
	}

	return $key;
}

/**
 * Takes a sequence of arrays containing characters. Will compute all the possible unique strings that can be
 * generated with those characters in those positions in the string.
 *
 * returns an array of strings that represents all the found keys
 */
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

/**
 * @param $key : string representing the key
 * @param $originalBytes : array of hashbytes representing the ciphertext
 * @param $map : the vigenere ciper map
 * @return string : a binary string that is the output of the decryption.
 */
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

/** 
        Takes an int and computes if the int is within displayable ASCII. 
        If true, returns int which was given.
        If false, returns FALSE 
*/

function isPrintable($asciiNum) {
    if (($asciiNum > 31 && $asciiNum < 127) || $asciiNum == 9 || $asciiNum == 10 || $asciiNum == 13) {
        return($asciiNum);
    }
    else {
        return(FALSE);
    }
}



