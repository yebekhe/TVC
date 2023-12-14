<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

// Fetch the JSON data from the API and decode it into an associative array
$sourcesArray = json_decode(
    file_get_contents("https://api.yebekhe.link/tvc-channels/channels.json"),
    true
);

// Count the total number of sources
$totalSources = count($sourcesArray);
$tempCounter = 1;

// Initialize an empty array to store the configurations
$configsList = [];
echo "Fetching Configs\n";

// Loop through each source in the sources array
foreach ($sourcesArray as $source => $types) {
    // Calculate the percentage complete
    $percentage = ($tempCounter / $totalSources) * 100;

    // Print the progress bar
    echo "\rProgress: [";
    echo str_repeat("=", $tempCounter);
    echo str_repeat(" ", $totalSources - $tempCounter);
    echo "] $percentage%";
    $tempCounter++;
    
    // Fetch the data from the source
    $tempData = file_get_contents("https://t.me/s/" . $source);
    $type = implode("|", $types);
    $tempExtract = extractLinksByType($tempData, $type);
    if (!is_null($tempExtract)) {
        $configsList[$source] = $tempExtract;
    }
}

// Initialize an empty array to store the final output
$finalOutput = [];
$locationBased = [];
$needleArray = ["amp%3B"];
$replaceArray = [""];

// Define the hash and IP keys for each type of configuration
$configsHash = [
    "vmess" => "ps",
    "vless" => "hash",
    "trojan" => "hash",
    "tuic" => "hash",
    "hy2" => "hash",
    "ss" => "name",
];
$configsIp = [
    "vmess" => "add",
    "vless" => "hostname",
    "trojan" => "hostname",
    "tuic" => "hostname",
    "hy2" => "hostname",
    "ss" => "server_address",
];

echo "\nProcessing Configs\n";
$totalSources = count($configsList);
$tempSource = 1;

// Loop through each source in the configs list
foreach ($configsList as $source => $configs) {
    $totalConfigs = count($configs);
    $tempCounter = 1;
    echo "\n" . strval($tempSource) . "/" . strval($totalSources) . "\n";

    // Loop through each config in the configs array
    $limitKey = count($configs) - 15;
    foreach (array_reverse($configs) as $key => $config) {
        // Calculate the percentage complete
        $percentage = ($tempCounter / $totalConfigs) * 100;

        // Print the progress bar
        echo "\rProgress: [";
        echo str_repeat("=", $tempCounter);
        echo str_repeat(" ", $totalConfigs - $tempCounter);
        echo "] $percentage%";
        $tempCounter++;

        // If the config is valid and the key is less than or equal to 15
        if (is_valid($config) && $key >= $limitKey) {
            $type = detect_type($config);
            $configHash = $configsHash[$type];
            $configIp = $configsIp[$type];
            $decodedConfig = configParse(explode("<", $config)[0]);
            $configLocation =
                ip_info($decodedConfig[$configIp])->country ?? "XX";
            $configFlag =
                $configLocation === "XX" ? "🏳️" : getFlags($configLocation);
            $source = $source === "iP_CF" ? "FAKEOFTVC" : $source;
            $decodedConfig[$configHash] =
                $configFlag .
                $configLocation .
                " | " .
                $type .
                " | @" .
                $source .
                " | " .
                strval($key);
            $encodedConfig = reparseConfig($decodedConfig, $type);
            $finalOutput[] = str_replace(
                $needleArray,
                $replaceArray,
                $encodedConfig
            );
            $locationBased[$configLocation][] = str_replace(
                $needleArray,
                $replaceArray,
                $encodedConfig
            );
        }
    }
    $tempSource++;
}

// Loop through each location in the location-based array
foreach ($locationBased as $location => $configs) {
    $tempConfig = urldecode(implode("\n", $configs));
    $base64TempConfig = base64_encode($tempConfig);
    file_put_contents(
        "subscriptions/location/normal/" . $location,
        $tempConfig
    );
    file_put_contents(
        "subscriptions/location/base64/" . $location,
        $base64TempConfig
    );
}

// Write the final output to a file
file_put_contents("config.txt", implode("\n", $finalOutput));

echo "\nGetting Configs Done!\n";
