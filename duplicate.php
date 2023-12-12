<?php
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

require "functions.php";

$configsHash = [
    "vmess" => "ps",
    "vless" => "hash",
    "trojan" => "hash",
    "tuic" => "hash",
    "hy2" => "hash",
    "ss" => "name",
];
$configsArray = explode("\n", file_get_contents("config.txt"));

$deduplicateArray = [];
$namesArray = [];

foreach ($configsArray as $config) {
    $configType = detect_type($config);
    $configHash = $configsHash[$configType];
    $decodedConfig = configParse($config);
    $tempHash = $decodedConfig[$configHash];
    unset($decodedConfig[$configHash]);
    $encodedConfig = reparseConfig($decodedConfig, $configType);
    if (!in_array($encodedConfig, $deduplicateArray)) {
        $namesArray[] = $tempHash;
        $deduplicateArray[] = $encodedConfig;
    }
}

$finalOutput = [];

foreach ($deduplicateArray as $key => $deduplicate) {
    $configType = detect_type($deduplicate);
    $configHash = $configsHash[$configType];
    $decodedConfig = configParse($deduplicate);
    $decodedConfig[$configHash] = $namesArray[$key];
    $encodedConfig = reparseConfig($decodedConfig, $configType);
    $finalOutput[] = $encodedConfig;
}

file_put_contents("config.txt", implode("\n", $finalOutput));
file_put_contents("subscriptions/xray/normal/mix", implode("\n", $finalOutput));
file_put_contents(
    "subscriptions/xray/base64/mix",
    implode("\n", base64_encode($finalOutput))
);

echo "done!";
