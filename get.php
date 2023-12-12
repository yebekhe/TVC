<?php
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

require "functions.php";

$sourcesArray = json_decode(
    file_get_contents("https://api.yebekhe.link/tvc-channels/channels.json"),
    true
);
$totalSources = count($sourcesArray);
$tempCounter = 1;

$configsList = [];
echo "Fetching Configs\n";
foreach ($sourcesArray as $source => $types) {
    // Calculate the percentage complete
    $percentage = ($tempCounter / $totalSources) * 100;

    // Print the progress bar
    echo "\rProgress: [";
    echo str_repeat("=", $tempCounter);
    echo str_repeat(" ", $totalSources - $tempCounter);
    echo "] $percentage%";
    $tempCounter++;
    $tempData = file_get_contents("https://t.me/s/" . $source);
    $type = implode("|", $types);
    $tempExtract = extractLinksByType($tempData, $type);
    if (!is_null($tempExtract)) {
        $configsList[$source] = $tempExtract;
    }
}
$finalOutput = [];
$locationBased = [];
$needleArray = ["amp%3B"];
$replaceArray = [""];
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
foreach ($configsList as $source => $configs) {
    $totalConfigs = count($configs);
    $tempCounter = 1;
    echo "\n" . strval($tempSource) . "/" . strval($totalSources) . "\n";
    foreach ($configs as $key => $config) {
        // Calculate the percentage complete
        $percentage = ($tempCounter / $totalConfigs) * 100;

        // Print the progress bar
        echo "\rProgress: [";
        echo str_repeat("=", $tempCounter);
        echo str_repeat(" ", $totalConfigs - $tempCounter);
        echo "] $percentage%";
        $tempCounter++;
        if (is_valid($config) && $key <= 9 ) {
            $type = detect_type($config);
            $configHash = $configsHash[$type];
            $configIp = $configsIp[$type];
            $decodedConfig = configParse(explode("<", $config)[0]);
            $configLocation =
                ip_info($decodedConfig[$configIp])->country ?? "XX";
            $configFlag =
                $configLocation === "XX" ? "🏳️" : getFlags($configLocation);
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

foreach ($locationBased as $location => $configs) {
    $tempConfig = implode("\n", $configs);
    file_put_contents("subscriptions/location/normal/" . $location, $tempConfig);
    file_put_contents("subscriptions/location/base64/" . base64_encode($tempConfig));
}

file_put_contents("config.txt", implode("\n", $finalOutput));

echo "done!";
