<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "lite/functions.php";

// Read the config.txt file and split it into an array by newline
$configsArray = explode("\n", file_get_contents("config.txt"));

// Initialize an empty array to hold the sorted configurations
$sortArray = [];

// Loop through each configuration in the configsArray
foreach ($configsArray as $config) {
    // Detect the type of the configuration
    $configType = detect_type($config);
    // Add the configuration to the corresponding array in sortArray
    $sortArray[$configType][] = $config;
    // If the configuration is of type "vless" and is a reality, add it to the "reality" array
    if ($configType === "vless" && is_reality($config)) {
        $sortArray["reality"][] = $config;
    }
}

// Loop through each type of configuration in sortArray
foreach ($sortArray as $type => $sort) {
    // If the type is not empty
    if ($type !== "") {
        // Join the configurations into a string, encode it to base64, and write it to a file
        $tempConfigs = hiddifyHeader("TVC | " . strtoupper($type)) . implode("\n", $sort);
        $base64TempConfigs = base64_encode($tempConfigs);
        file_put_contents("lite/subscriptions/xray/normal/" . $type, $tempConfigs);
        file_put_contents(
            "lite/subscriptions/xray/base64/" . $type,
            $base64TempConfigs
        );
    }
}

// Print "done!" to the console
echo "Sorting Done!";
