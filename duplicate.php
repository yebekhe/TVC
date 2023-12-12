<?php
error_reporting(0);
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

function configParse($input)
{
    $configType = detect_type($input);
    if ($configType === "vmess") {
        $vmess_data = substr($input, 8);
        $decoded_data = json_decode(base64_decode($vmess_data), true);
        return $decoded_data;
    } elseif (
        $configType === "vless" ||
        $configType === "trojan" ||
        $configType === "tuic" ||
        $configType === "hy2"
    ) {
        $parsedUrl = parse_url($input);
        $params = [];
        if (isset($parsedUrl["query"])) {
            parse_str($parsedUrl["query"], $params);
        }
        $output = [
            "protocol" => $configType,
            "username" => isset($parsedUrl["user"]) ? $parsedUrl["user"] : "",
            "hostname" => isset($parsedUrl["host"]) ? $parsedUrl["host"] : "",
            "port" => isset($parsedUrl["port"]) ? $parsedUrl["port"] : "",
            "params" => $params,
            "hash" => isset($parsedUrl["fragment"])
                ? $parsedUrl["fragment"]
                : "",
        ];

        if ($configType === "tuic") {
            $output["pass"] = isset($parsedUrl["pass"])
                ? $parsedUrl["pass"]
                : "";
        }
        return $output;
    } elseif ($configType === "ss") {
        $url = parse_url($input);
        list($encryption_method, $password) = explode(
            ":",
            base64_decode($url["user"])
        );
        $server_address = $url["host"];
        $server_port = $url["port"];
        $name = isset($url["fragment"]) ? urldecode($url["fragment"]) : null;
        $server = [
            "encryption_method" => $encryption_method,
            "password" => $password,
            "server_address" => $server_address,
            "server_port" => $server_port,
            "name" => $name,
        ];
        return $server;
    }
}

function reparseConfig($configArray, $configType)
{
    if ($configType === "vmess") {
        $encoded_data = base64_encode(json_encode($configArray));
        $vmess_config = "vmess://" . $encoded_data;
        return $vmess_config;
    } elseif (
        $configType === "vless" ||
        $configType === "trojan" ||
        $configType === "tuic" ||
        $configType === "hy2"
    ) {
        $url = $configType . "://";
        $url .= addUsernameAndPassword($configArray);
        $url .= $configArray["hostname"];
        $url .= addPort($configArray);
        $url .= addParams($configArray);
        $url .= addHash($configArray);
        return $url;
    } elseif ($configType === "ss") {
        $user = base64_encode(
            $configArray["encryption_method"] . ":" . $configArray["password"]
        );
        $url = "ss://$user@{$configArray["server_address"]}:{$configArray["server_port"]}";
        if (!empty($configArray["name"])) {
            $url .= "#" . urlencode($configArray["name"]);
        }
        return $url;
    }
}

function addUsernameAndPassword($obj)
{
    $url = "";
    if ($obj["username"] !== "") {
        $url .= $obj["username"];
        if (isset($obj["pass"]) && $obj["pass"] !== "") {
            $url .= ":" . $obj["pass"];
        }
        $url .= "@";
    }
    return $url;
}

function addPort($obj)
{
    $url = "";
    if (isset($obj["port"]) && $obj["port"] !== "") {
        $url .= ":" . $obj["port"];
    }
    return $url;
}

function addParams($obj)
{
    $url = "";
    if (!empty($obj["params"])) {
        $url .= "?" . http_build_query($obj["params"]);
    }
    return $url;
}

function addHash($obj)
{
    $url = "";
    if (isset($obj["hash"]) && $obj["hash"] !== "") {
        $url .= "#" . $obj["hash"];
    }
    return $url;
}
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
unlink("config.txt");
file_put_contents("subscription/normal/mix", implode("\n", $finalOutput));

echo "done!";


