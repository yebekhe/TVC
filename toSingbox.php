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
    } 
    
  return null;
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
                : "TVC",
        ];

        if ($configType === "tuic") {
            $output["pass"] = isset($parsedUrl["pass"])
                ? $parsedUrl["pass"]
                : "";
        }
        return $output;
    } elseif ($configType === "ss") {
        $url = parse_url($input);
        if (isBase64($url["user"])) {
            $url["user"] = base64_decode($url["user"]);
        }
        list($encryption_method, $password) = explode(
            ":",
            $url["user"]
        );
        $server_address = $url["host"];
        $server_port = $url["port"];
        $name = isset($url["fragment"]) ? urldecode($url["fragment"]) : "TVC";
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

function setTls ($decodeConfig, $configType) {
    $serverNameTypes = [
        "vmess" => $decodeConfig["sni"] ?? $decodeConfig["add"],
        "vless" => $decodeConfig["params"]["sni"] ?? $decodeConfig["hostname"],
        "trojan" => $decodeConfig["params"]["sni"] ?? $decodeConfig["hostname"],
        "tuic" => $decodeConfig["params"]["sni"] ?? $decodeConfig["hostname"],
        "hy2" => $decodeConfig["params"]["sni"] ?? $decodeConfig["hostname"]
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

function setTransport ($decodeConfig, $configType, $transportType) {
    $serverNameTypes = [
        "vmess" => $decodeConfig["sni"] ?? $decodeConfig["add"],
        "vless" => $decodeConfig["params"]["sni"] ?? $decodeConfig["hostname"],
        "trojan" => $decodeConfig["params"]["sni"] ?? $decodeConfig["hostname"],
        "tuic" => $decodeConfig["params"]["sni"] ?? $decodeConfig["hostname"],
        "hy2" => $decodeConfig["params"]["sni"] ?? $decodeConfig["hostname"]
    ];
    $pathTypes = [
        "vmess" => processWsPath($decodeConfig["path"])['path'],
        "vless" => processWsPath($decodeConfig["params"]["path"])["path"],
        "trojan" => processWsPath($decodeConfig["params"]["path"])["path"],
        "tuic" => processWsPath($decodeConfig["params"]["path"])["path"],
        "hy2" => processWsPath($decodeConfig["params"]["path"])["path"]
    ];
    $servicenameTypes = [
        "vmess" => $decodeConfig["path"],
        "vless" => $decodeConfig["params"]["serviceName"] ?? "",
        "trojan" => $decodeConfig["params"]["serviceName"] ?? "",
        "tuic" => $decodeConfig["params"]["serviceName"] ?? "",
        "hy2" => $decodeConfig["params"]["serviceName"] ?? "",
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

function setReality ($decodeConfig) {
    return [
        "enabled" => true,
        "public_key" => $decodeConfig["params"]["pbk"] ?? '',
        "short_id" => $decodeConfig["params"]["sid"] ?? '',
    ];
}

function vmessToSingbox ($input) {
    $decodeConfig = configParse($input);

    $configResult = [
        "tag" => $decodeConfig["ps"],
        "type" => "vmess",
        "server" => $decodeConfig["add"],
        "server_port" => intval($decodeConfig["port"]),
        "uuid" => $decodeConfig["id"],
        "security" => "auto",
        "alter_id" => intval($decodeConfig["aid"]),
        "global_padding" => false,
        "authenticated_length" => true,
        "packet_encoding" => "",
        "multiplex" => [
            "enabled" => false,
            "protocol" => "smux",
            "max_streams" => 32,
        ],
    ];
    if (($decodeConfig["port"] === "443" || $decodeConfig["tls"] === "tls"))
    {
        $configResult["tls"] = setTls($decodeConfig, "vmess");
    }
    if (in_array($decodeConfig["net"], ["ws", "grpc", "http"])) $configResult["transport"] = setTransport($decodeConfig, "vmess", $decodeConfig["net"]);
    if (
        $decodeConfig["net"] === "grpc" &&
        ($configResult["transport"]["service_name"] === "" ||
            is_null($configResult["transport"]["service_name"]))
    ) {
        return null;
    }
    return $configResult;
}

function vlessToSingbox ($input) {
    $decodeConfig = configParse($input);
    $configResult = [
        "tag" => $decodeConfig["hash"],
        "type" => "vless",
        "server" => $decodeConfig["hostname"],
        "server_port" => intval($decodeConfig["port"]),
        "uuid" => $decodeConfig["username"],
        "flow" => !is_null($decodeConfig["params"]["flow"])
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
        $decodeConfig["port"] === "443" ||
        $decodeConfig["params"]["security"] === "tls" ||
        $decodeConfig["params"]["security"] === "reality"
    )
    {
        $configResult["tls"] = setTls($decodeConfig, "vless");
    }

    if (
        $decodeConfig["params"]["security"] === "reality" ||
        isset($decodeConfig["params"]["pbk"])
    ) 
    {
        $configResult["tls"]["reality"] = setReality($decodeConfig);
        if (
            is_null($decodeConfig["params"]["pbk"]) or
            $decodeConfig["params"]["pbk"] === ""
        ) {
            return null;
        }
    }
    if (in_array($decodeConfig["params"]["type"], ["ws", "grpc", "http"])) $configResult["transport"] = setTransport($decodeConfig, "vless", $decodeConfig["params"]["type"]);
    if (
        $decodeConfig["params"]["type"] === "grpc" &&
        ($configResult["transport"]["service_name"] === "" ||
            is_null($configResult["transport"]["service_name"]))
    ) {
        return null;
    }
    return $configResult;
}

function trojanToSingbox ($input) {
    $decodeConfig = configParse($input);
    $configResult = [
        "tag" => urldecode($decodeConfig["hash"]),
        "type" => "trojan",
        "server" => $decodeConfig["hostname"],
        "server_port" => intval($decodeConfig["port"]),
        "password" => $decodeConfig["username"],
        "multiplex" => [
            "enabled" => false,
            "protocol" => "smux",
            "max_streams" => 32,
        ],
    ];
    if (
        $decodeConfig["port"] === "443" ||
        $decodeConfig["params"]["security"] === "tls"
    ) {
        $configResult["tls"] = setTls($decodeConfig, "trojan");
    }
    if (in_array($decodeConfig["params"]["type"], ["ws", "grpc", "http"])) $configResult["transport"] = setTransport($decodeConfig, "trojan", $decodeConfig["params"]["type"]);
    if (
        $decodeConfig["params"]["type"] === "grpc" &&
        ($configResult["transport"]["service_name"] === "" ||
            is_null($configResult["transport"]["service_name"]))
    ) {
        return null;
    }
    return $configResult;
}

function ssToSingbox ($input) {
    $decodeConfig = configParse($input);
    if ($decodeConfig["encryption_method"] === "chacha20-poly1305") {
        return null;
    }
    $configResult = [
        "tag" => $decodeConfig["name"],
        "type" => "shadowsocks",
        "server" => $decodeConfig["server_address"],
        "server_port" => intval($decodeConfig["server_port"]),
        "method" => $decodeConfig["encryption_method"],
        "password" => $decodeConfig["password"],
        "plugin" => "",
        "plugin_opts" => "",
    ];
    return $configResult;
}

function tuicToSingbox ($input) {
    $decodeConfig = configParse($input);
    $configResult = [
        "tag" => urldecode($decodeConfig["hash"]),
        "server" => $decodeConfig["hostname"],
        "server_port" => intval($decodeConfig["port"]),
        "uuid" => $decodeConfig["username"],
        "password" => $decodeConfig["pass"],
        "congestion_control" => $decodeConfig["params"]["congestion_control"],
        "udp_relay_mode" => $decodeConfig["params"]["udp_relay_mode"],
        "zero_rtt_handshake" => false,
        "heartbeat" => "10s",
        "network" => "tcp",
    ];

    $configResult["tls"] = [
        "enabled" => true,
        "disable_sni" => isset($decodeConfig["params"]["sni"]) ? false : true,
        "server_name" => isset($decodeConfig["params"]["sni"])
            ? $decodeConfig["params"]["sni"]
            : "",
        "insecure" =>
            isset($decodeConfig["params"]["allow_insecure"]) &&
            intval($decodeConfig["params"]["allow_insecure"]) === 1
                ? true
                : false,
        "alpn" => ["h3", "spdy/3.1"],
    ];
    if (
        !isset($decodeConfig["params"]["alpn"]) ||
        is_null($decodeConfig["params"]["alpn"]) ||
        $decodeConfig["params"]["alpn"] === ""
    ) {
        unset($configResult["tls"]["alpn"]);
    }

    return $configResult;
}

function hy2ToSingbox ($input) {
    $decodeConfig = configParse($input);
    $configResult = [
        "tag" => urldecode($decodeConfig["hash"]),
        "type" => "hysteria2",
        "server" => $decodeConfig["hostname"],
        "server_port" => intval($decodeConfig["port"]),
        "up_mbps" => 0,
        "down_mbps" => 0,
        "password" => $decodeConfig["username"],
        "network" => "tcp",
    ];

    $configResult["obfs"] = [
        "type" => $decodeConfig["params"]["obfs"],
        "password" => $decodeConfig["params"]["obfs-password"],
    ];

    $configResult["tls"] = [
        "enabled" => true,
        "disable_sni" => isset($decodeConfig["params"]["sni"]) ? false : true,
        "server_name" => isset($decodeConfig["params"]["sni"])
            ? $decodeConfig["params"]["sni"]
            : "",
        "insecure" =>
            isset($decodeConfig["params"]["insecure"]) &&
            intval($decodeConfig["params"]["insecure"]) === 1
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
    $outbounds = $structure['outbound'];
    $manualOutbound = $outbounds[0];
    $urltestOutbound = $outbounds[1];
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
