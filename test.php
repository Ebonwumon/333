<?php

require_once('hash_lib.php');

$arr1 = array(1, 2, 3);

$arr2 = $arr1;

unset($arr1[1]);

print_r($arr1);
print_r($arr2);
