<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

function processWsPath($input)
{
    if (strpos($input, "/") === 0) {
        $input = substr($input, 1);
    }
    $max_early_data = 0;
    if (strpos($input, "?ed=2048") !== false) {
        $input = str_replace("?ed=2048", "", $input);
        $max_early_data = 2048;
    }
    $output = [
        "path" => "/" . $input,
        "max_early_data" => $max_early_data,
    ];

    return $output;
}

function setTls ($decodedConfig, $configType) {
    $serverNameTypes = [
        "vmess" => $decodedConfig["sni"] ?? $decodedConfig["add"],
        "vless" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"],
        "trojan" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"],
        "tuic" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"],
        "hy2" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"]
    ];
    return [
        "enabled" => true,
        "server_name" => $serverNameTypes[$configType],
        "insecure" => true,
        "disable_sni" => false,
        "utls" => [
            "enabled" => true,
            "fingerprint" => "chrome",
        ],
    ];
}

function setTransport ($decodedConfig, $configType, $transportType) {
    $serverNameTypes = [
        "vmess" => $decodedConfig["sni"] ?? $decodedConfig["add"],
        "vless" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"],
        "trojan" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"],
        "tuic" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"],
        "hy2" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"]
    ];
    $pathTypes = [
        "vmess" => processWsPath($decodedConfig["path"])['path'],
        "vless" => processWsPath($decodedConfig["params"]["path"])["path"],
        "trojan" => processWsPath($decodedConfig["params"]["path"])["path"],
        "tuic" => processWsPath($decodedConfig["params"]["path"])["path"],
        "hy2" => processWsPath($decodedConfig["params"]["path"])["path"]
    ];
    $servicenameTypes = [
        "vmess" => $decodedConfig["path"],
        "vless" => $decodedConfig["params"]["serviceName"] ?? "",
        "trojan" => $decodedConfig["params"]["serviceName"] ?? "",
        "tuic" => $decodedConfig["params"]["serviceName"] ?? "",
        "hy2" => $decodedConfig["params"]["serviceName"] ?? "",
    ];
    $transportTypes = [
        "ws" => [
            "type" => "ws",
            "path" => $pathTypes[$configType],
            "headers" => [
                "Host" => $serverNameTypes[$configType]
            ],
        ],
        "grpc" => [
            "type" => "grpc",
            "service_name" => $servicenameTypes[$configType],
            "idle_timeout" => "15s",
            "ping_timeout" => "15s",
            "permit_without_stream" => false,
        ],
        "http" => [
            "type" => "http",
            "host" => [
                $serverNameTypes[$configType]
            ],
            "path" => $pathTypes[$configType],
        ]
    ];
    return $transportTypes[$transportType];
}

function setReality ($decodedConfig) {
    return [
        "enabled" => true,
        "public_key" => $decodedConfig["params"]["pbk"] ?? '',
        "short_id" => $decodedConfig["params"]["sid"] ?? '',
    ];
}

function vmessToSingbox ($input) {
    $decodedConfig = configParse($input);

    $configResult = [
        "tag" => $decodedConfig["ps"],
        "type" => "vmess",
        "server" => $decodedConfig["add"],
        "server_port" => intval($decodedConfig["port"]),
        "uuid" => $decodedConfig["id"],
        "security" => "auto",
        "alter_id" => intval($decodedConfig["aid"]),
        "global_padding" => false,
        "authenticated_length" => true,
        "packet_encoding" => "",
        "multiplex" => [
            "enabled" => false,
            "protocol" => "smux",
            "max_streams" => 32,
        ],
    ];
    if (($decodedConfig["port"] === "443" || $decodedConfig["tls"] === "tls"))
    {
        $configResult["tls"] = setTls($decodedConfig, "vmess");
    }
    if (in_array($decodedConfig["net"], ["ws", "grpc", "http"])) $configResult["transport"] = setTransport($decodedConfig, "vmess", $decodedConfig["net"]);
    if (
        $decodedConfig["net"] === "grpc" &&
        ($configResult["transport"]["service_name"] === "" ||
            is_null($configResult["transport"]["service_name"]))
    ) {
        return null;
    }
    return $configResult;
}

function vlessToSingbox ($input) {
    $decodedConfig = configParse($input);
    $configResult = [
        "tag" => $decodedConfig["hash"],
        "type" => "vless",
        "server" => $decodedConfig["hostname"],
        "server_port" => intval($decodedConfig["port"]),
        "uuid" => $decodedConfig["username"],
        "flow" => !is_null($decodedConfig["params"]["flow"])
            ? "xtls-rprx-vision"
            : "",
        "packet_encoding" => "xudp",
        "multiplex" => [
            "enabled" => false,
            "protocol" => "smux",
            "max_streams" => 32,
        ],
    ];
    if (
        $decodedConfig["port"] === "443" ||
        $decodedConfig["params"]["security"] === "tls" ||
        $decodedConfig["params"]["security"] === "reality"
    )
    {
        $configResult["tls"] = setTls($decodedConfig, "vless");
    }

    if (
        $decodedConfig["params"]["security"] === "reality" ||
        isset($decodedConfig["params"]["pbk"])
    ) 
    {
        $configResult["tls"]["reality"] = setReality($decodedConfig);
        $configResult["tls"]["utls"]["fingerprint"] = $decodedConfig["params"]["fp"];
        $configResult['flow'] = "xtls-rprx-vision";
        if (
            is_null($decodedConfig["params"]["pbk"]) or
            $decodedConfig["params"]["pbk"] === ""
        ) {
            return null;
        }
    }
    if (in_array($decodedConfig["params"]["type"], ["ws", "grpc", "http"])) $configResult["transport"] = setTransport($decodedConfig, "vless", $decodedConfig["params"]["type"]);
    if (
        $decodedConfig["params"]["type"] === "grpc" &&
        ($configResult["transport"]["service_name"] === "" ||
            is_null($configResult["transport"]["service_name"]))
    ) {
        return null;
    }
    return $configResult;
}

function trojanToSingbox ($input) {
    $decodedConfig = configParse($input);
    $configResult = [
        "tag" => urldecode($decodedConfig["hash"]),
        "type" => "trojan",
        "server" => $decodedConfig["hostname"],
        "server_port" => intval($decodedConfig["port"]),
        "password" => $decodedConfig["username"],
        "multiplex" => [
            "enabled" => false,
            "protocol" => "smux",
            "max_streams" => 32,
        ],
    ];
    if (
        $decodedConfig["port"] === "443" ||
        $decodedConfig["params"]["security"] === "tls"
    ) {
        $configResult["tls"] = setTls($decodedConfig, "trojan");
    }
    if (in_array($decodedConfig["params"]["type"], ["ws", "grpc", "http"])) $configResult["transport"] = setTransport($decodedConfig, "trojan", $decodedConfig["params"]["type"]);
    if (
        $decodedConfig["params"]["type"] === "grpc" &&
        ($configResult["transport"]["service_name"] === "" ||
            is_null($configResult["transport"]["service_name"]))
    ) {
        return null;
    }
    return $configResult;
}

function ssToSingbox ($input) {
    $decodedConfig = configParse($input);
    $encryptionMethodes = [
        "chacha20-ietf-poly1305",
        "aes-256-gcm",
        "2022-blake3-aes-256-gcm"
    ];
    if (!in_array($decodedConfig["encryption_method"], $encryptionMethodes)) {
        return null;
    }
    
    $configResult = [
        "tag" => $decodedConfig["name"],
        "type" => "shadowsocks",
        "server" => $decodedConfig["server_address"],
        "server_port" => intval($decodedConfig["server_port"]),
        "method" => $decodedConfig["encryption_method"],
        "password" => $decodedConfig["password"],
        "plugin" => "",
        "plugin_opts" => "",
    ];
    return $configResult;
}

function tuicToSingbox ($input) {
    $decodedConfig = configParse($input);
    $configResult = [
        "tag" => urldecode($decodedConfig["hash"]),
        "type" => "tuic",
        "server" => $decodedConfig["hostname"],
        "server_port" => intval($decodedConfig["port"]),
        "uuid" => $decodedConfig["username"],
        "password" => $decodedConfig["pass"],
        "congestion_control" => $decodedConfig["params"]["congestion_control"],
        "udp_relay_mode" => $decodedConfig["params"]["udp_relay_mode"],
        "zero_rtt_handshake" => false,
        "heartbeat" => "10s",
        "network" => "tcp",
    ];

    $configResult["tls"] = [
        "enabled" => true,
        "disable_sni" => isset($decodedConfig["params"]["sni"]) ? false : true,
        "server_name" => isset($decodedConfig["params"]["sni"])
            ? $decodedConfig["params"]["sni"]
            : "",
        "insecure" =>
            isset($decodedConfig["params"]["allow_insecure"]) &&
            intval($decodedConfig["params"]["allow_insecure"]) === 1
                ? true
                : false,
        "alpn" => ["h3", "spdy/3.1"],
    ];
    if (
        !isset($decodedConfig["params"]["alpn"]) ||
        is_null($decodedConfig["params"]["alpn"]) ||
        $decodedConfig["params"]["alpn"] === ""
    ) {
        unset($configResult["tls"]["alpn"]);
    }

    return $configResult;
}

function hy2ToSingbox ($input) {
    $decodedConfig = configParse($input);
    $configResult = [
        "tag" => urldecode($decodedConfig["hash"]),
        "type" => "hysteria2",
        "server" => $decodedConfig["hostname"],
        "server_port" => intval($decodedConfig["port"]),
        "up_mbps" => 0,
        "down_mbps" => 0,
        "password" => $decodedConfig["username"],
        "network" => "tcp",
    ];

    $configResult["obfs"] = [
        "type" => $decodedConfig["params"]["obfs"],
        "password" => $decodedConfig["params"]["obfs-password"],
    ];

    $configResult["tls"] = [
        "enabled" => true,
        "disable_sni" => isset($decodedConfig["params"]["sni"]) ? false : true,
        "server_name" => isset($decodedConfig["params"]["sni"])
            ? $decodedConfig["params"]["sni"]
            : "",
        "insecure" =>
            isset($decodedConfig["params"]["insecure"]) &&
            intval($decodedConfig["params"]["insecure"]) === 1
                ? true
                : false,
        "alpn" => ["h3"],
    ];

    return $configResult;

}

function toSingbox ($input) {
    $configType = detect_type($input);
    $functionsArray = [
        "vmess" => "vmessToSingbox",
        "vless" => "vlessToSingbox",
        "trojan" => "trojanToSingbox",
        "tuic" => "tuicToSingbox",
        "hy2" => "hy2ToSingbox",
        "ss" => "ssToSingbox",
    ];
    return $functionsArray[$configType]($input);
}

function processConvertion ($base64ConfigsList, $configsName = "Created By YeBeKhe") {
    $configsArray = explode("\n", base64_decode($base64ConfigsList));
    $structure = json_decode(file_get_contents('structure.json'), true);
    foreach ($configsArray as $config) {
        $toSingbox = toSingbox($config);
        if (!is_null($toSingbox)) {
            $structure['outbounds'][] = $toSingbox;
            $structure['outbounds'][0]['outbounds'][] = $toSingbox['tag'];
            $structure['outbounds'][1]['outbounds'][] = $toSingbox['tag'];
        }
    }
    $headerText = "//profile-title: base64:" . base64_encode($configsName) . "
//profile-update-interval: 1
//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
//support-url: https://t.me/V2rayCollector
//profile-web-page-url: https://t.me/V2rayCollectorBot

";
    return $headerText . json_encode($structure, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}

$directoryOfFiles = [
    "subscriptions/xray/base64/mix",
    "subscriptions/xray/base64/vmess",
    "subscriptions/xray/base64/vless",
    "subscriptions/xray/base64/reality",
    "subscriptions/xray/base64/tuic",
    "subscriptions/xray/base64/hy2",
    "subscriptions/xray/base64/ss",
];

foreach ($directoryOfFiles as $directory) {
    $configsName = "TVC | " . explode("/", $directory)[3];
    $configsData = file_get_contents($directory);
    $convertionResult = processConvertion($configsData, $configsName);
    file_put_contents("subscriptions/singbox/" . explode("/", $directory)[3] . ".json", $convertionResult);
}

echo "Convertion To Singbox Done!\n";
