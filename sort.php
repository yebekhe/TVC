<?php
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

require "functions.php";

$configsArray = explode("\n", file_get_contents("config.txt"));

$sortArray = [];

foreach ($configsArray as $config) {
    $configType = detect_type($config);
    $sortArray[$configType][] = $config;
    if ($configType === "vless" && is_reality($config)) {
        $sortArray["reality"][] = $config;
    }
}

foreach ($sortArray as $type => $sort) {
    if ($type !== "") {
        $tempConfigs = implode("\n", $sort);
        $base64TempConfigs = base64_encode($tempConfigs);
        file_put_contents("subscriptions/xray/normal/" . $type, $tempConfigs);
        file_put_contents(
            "subscriptions/xray/base64/" . $type,
            $base64TempConfigs
        );
        file_put_contents(
            "subscriptions/singbox/" . $type . ".json",
            toSingbox($base64TempConfigs)
        );
        file_put_contents(
            "subscriptions/clash/" . $type . ".yaml",
            toClash($base64TempConfigs, "clash")
        );
        file_put_contents(
            "subscriptions/meta/" . $type . ".yaml",
            toClash($base64TempConfigs, "meta")
        );
        file_put_contents(
            "subscriptions/surfboard/" . $type,
            toClash($base64TempConfigs, "surfboard")
        );
    }
}

echo "done!";
