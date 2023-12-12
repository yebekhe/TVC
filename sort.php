<?php

function detect_type($input)
{
    if (substr($input, 0, 8) === "vmess://") {
        return "vmess";
    } elseif (substr($input, 0, 8) === "vless://") {
        return "vless";
    } elseif (substr($input, 0, 9) === "trojan://") {
        return "trojan";
    } elseif (substr($input, 0, 5) === "ss://") {
        return "ss";
    } elseif (substr($input, 0, 7) === "tuic://") {
        return "tuic";
    } elseif (
        substr($input, 0, 6) === "hy2://" ||
        substr($input, 0, 12) === "hysteria2://"
    ) {
        return "hy2";
    } elseif (
        substr($input, 0, 11) === "hysteria://"
    ) {
        return "hysteria";
    }
}

function is_reality($input)
{
    $type = detect_type($input);
    if (stripos($input, "reality") !== false && $type === "vless") {
        return true;
    }
    return false;
}

$configsArray = explode("\n", file_get_contents("config.txt"));

$sortArray = [];

foreach($configsArray as $config) {
    $configType = detect_type($config);
    $sortArray[$configType][] = $config;
    if ($configType === "vless" && is_reality($config)) {
        $sortArray["reality"][] = $config;
    }
}

foreach ($sortArray as $type => $sort) {
    if ($type !== "") {
        file_put_contents($type . ".txt", implode("\n", $sort));
    }
}

echo "done!";
