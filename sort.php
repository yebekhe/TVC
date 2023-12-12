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

function toSingbox(
    $configs
) {
    $url = "https://api.yebekhe.link/convertor/singbox/index.php";

    $data = [
        "config" => $configs,
        "limit" => 0,
        "tun" => true
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    $result = curl_exec($ch);
    curl_close($ch);

    return $result;
}

function toClash(
    $configs,
    $type
) {
    $url = "https://api.yebekhe.link/convertor/clash/index.php";

    $data = [
        "config" => $configs,
        "type" => $type,
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    $result = curl_exec($ch);
    curl_close($ch);

    return $result;
}


$configsArray = explode("\n", file_get_contents("subscription/xray/normal/mix"));

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
        $tempConfigs = implode("\n", $sort);
        file_put_contents("subscription/xray/normal/" . $type, $tempConfigs);
        file_put_contents("subscription/xray/base64/" . $type, base64_encode($tempConfigs));
        file_put_contents("subscription/singbox/" . $type . ".json", toSingbox($tempConfigs));
        file_put_contents("subscription/clash/" . $type . ".yaml", toClash($tempConfigs, "clash"));
        file_put_contents("subscription/meta/" . $type . ".yaml", toClash($tempConfigs, "meta"));
        file_put_contents("subscription/surfboard/" . $type, toClash($tempConfigs, "surfboard"));
    }
}

echo "done!";
