<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

// Define the hash for each config type
$configsHash = [
    "vmess" => "ps",
    "vless" => "hash",
    "trojan" => "hash",
    "tuic" => "hash",
    "hy2" => "hash",
    "ss" => "name",
];

// Read the config file and split it into an array by newline
$configsArray = explode("\n", file_get_contents("config.txt"));

$channelsAssets = json_decode(file_get_contents("channelsData/channelsAssets.json"), true);

// Initialize arrays to store deduplicated configs and their names
$deduplicateArray = [];
$namesArray = [];

// Loop through each config in the configsArray
foreach ($configsArray as $config) {
    // Detect the type of the config
    $configType = detect_type($config);
    // Get the hash for the config type
    $configHash = $configsHash[$configType];
    // Parse the config
    $decodedConfig = configParse($config);
    // Store the hash temporarily
    $tempHash = $decodedConfig[$configHash];
    // Remove the hash from the config
    unset($decodedConfig[$configHash]);
    // Reparse the config without the hash
    $encodedConfig = reparseConfig($decodedConfig, $configType);
    // If the config is not already in the deduplicateArray, add it
    if (!in_array($encodedConfig, $deduplicateArray)) {
        $namesArray[] = $tempHash;
        $deduplicateArray[] = $encodedConfig;
    }
}

// Initialize an array to store the final output
$finalOutput = [];

// Initialize an array to store the configs Full Data output
$configsFullData = [];

// Loop through each deduplicated config
foreach ($deduplicateArray as $key => $deduplicate) {
    // Detect the type of the config
    $configType = detect_type($deduplicate);
    // Get the hash for the config type
    $configHash = $configsHash[$configType];
    // Parse the config
    $decodedConfig = configParse($deduplicate);
    // Replace the hash with the name
    $decodedConfig[$configHash] = $namesArray[$key];
    // Reparse the config with the name
    $encodedConfig = reparseConfig($decodedConfig, $configType);
    // Add the config to the final output
    $finalOutput[] = $encodedConfig;

    $sourceUsername = str_replace(["%20", "@"], ["", ""], explode("|", $namesArray[$key])[2]);

    $configsFullData[$key]["channel"]["username"]  = $sourceUsername;
    $configsFullData[$key]["channel"]["title"] = $channelsAssets[$sourceUsername]['title'];
    $configsFullData[$key]["channel"]["logo"] = $channelsAssets[$sourceUsername]['logo'];
    $configsFullData[$key]['type'] = $configType === 'vless' && is_reality($encodedConfig) ? 'reality' : $configType;
    $configsFullData[$key]["config"] = $encodedConfig;

}

// Write the final output to the config file
file_put_contents("config.txt", implode("\n", $finalOutput));

$tempConfig = hiddifyHeader("TVC | MIX") . urldecode(implode("\n", $finalOutput));
$base64TempConfig = base64_encode($tempConfig);

// Write the final output to the subscriptions/xray/normal/mix file
file_put_contents("subscriptions/xray/normal/mix", $tempConfig);
// Write the final output to the subscriptions/xray/base64/mix file, encoded in base64
file_put_contents("subscriptions/xray/base64/mix", $base64TempConfig);

if (!file_exists('api/allConfigs.json')) {
    mkdir('api');
}
file_put_contents("api/allConfigs.json", json_encode($configsFullData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

// Print "done!" to the console
echo "Removing Duplicates Done!\n";
