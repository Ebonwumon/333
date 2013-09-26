<?php

require_once('hash_lib.php');


$key = str_split("hello");

//print($key["1"]);
$key = "2brodsky";
$originalBytes = getHashArrayFromFile("ciphertext1", $map);

$result = "";
$KEY_LENGTH = len($key);
$keyhash = array();
foreach (str_split($key) as $chr) {
    $keyhash[] = new HashByte(ord($chr));
}
for ($i = 0; $i < count($originalBytes); $i++) {
    $result .= chr(decodeByte($keyhash[$i % $KEY_LENGTH], $originalBytes[$i], $map));
}

return $result;

die();
$originalBytes = getHashArrayFromFile("ciphertext1", $map);
print(decryptWithKey("2brodsky", $originalBytes, $map));

die();

$arr1 = array(1, 2, 3);

$arr2 = $arr1;

unset($arr1[1]);

print_r($arr1);
print_r($arr2);
