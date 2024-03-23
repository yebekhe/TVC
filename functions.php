<?php

function is_ip($string)
{
    $ip_pattern = '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/';
    if (preg_match($ip_pattern, $string)) {
        return true;
    } else {
        return false;
    }
}

function ip_info($ip)
{
    if (is_ip($ip) === false) {
        $ip_address_array = dns_get_record($ip, DNS_A);
        if (empty($ip_address_array)) {
            return null;
        }
        $randomKey = array_rand($ip_address_array);
        $ip = $ip_address_array[$randomKey]["ip"];
    }

    // List of API endpoints
    $endpoints = [
        "https://ipapi.co/{ip}/json/",
        "https://ipwhois.app/json/{ip}",
        "http://www.geoplugin.net/json.gp?ip={ip}",
        "https://api.ipbase.com/v1/json/{ip}",
    ];

    // Initialize an empty result object
    $result = (object) [
        "country" => "XX",
    ];

    // Loop through each endpoint
    foreach ($endpoints as $endpoint) {
        // Construct the full URL
        $url = str_replace("{ip}", $ip, $endpoint);

        $options = [
            "http" => [
                "header" =>
                    "User-Agent: Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.102011-10-16 20:23:10\r\n", // i.e. An iPad
            ],
        ];

        $context = stream_context_create($options);
        $response = file_get_contents($url, false, $context);

        if ($response !== false) {
            $data = json_decode($response);

            // Extract relevant information and update the result object
            if ($endpoint == $endpoints[0]) {
                // Data from ipapi.co
                $result->country = $data->country_code ?? "XX";
            } elseif ($endpoint == $endpoints[1]) {
                // Data from ipwhois.app
                $result->country = $data->country_code ?? "XX";
            } elseif ($endpoint == $endpoints[2]) {
                // Data from geoplugin.net
                $result->country = $data->geoplugin_countryCode ?? "XX";
            } elseif ($endpoint == $endpoints[3]) {
                // Data from ipbase.com
                $result->country = $data->country_code ?? "XX";
            }
            // Break out of the loop since we found a successful endpoint
            break;
        }
    }

    return $result;
}

function is_valid($input)
{
    if (stripos($input, "…") !== false or stripos($input, "...") !== false) {
        return false;
    }
    return true;
}

function isEncrypted($input) {
    $decodedConfig = configParse($input);
    $configType = detect_type($input);

    if ($configType === "vmess" && $decodedConfig['tls'] !== "" && $decodedConfig['scy'] !== "none") {
        return true;
    } elseif (in_array($configType, ["vless", "trojan"]) && !empty($decodedConfig['params']['security']) && $decodedConfig['params']['security'] !== "none") {
        return true;
    } elseif ($configType === "ss") {
        return true;
    } elseif ($configType === "tuic" /*&& $decodedConfig['params']['allow_insecure'] === "0" && !empty($decodedConfig['params']['allow_insecure'])*/) {
        return true;
    } elseif ($configType === "hy2" /*&& $decodedConfig['params']['insecure'] === "0" && !empty($decodedConfig['params']['insecure'])*/) {
        return true;
    }
    return false;
}

function getFlags($country_code)
{
    $flag = mb_convert_encoding(
        "&#" . (127397 + ord($country_code[0])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
    $flag .= mb_convert_encoding(
        "&#" . (127397 + ord($country_code[1])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
    return $flag;
}

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
    } elseif (substr($input, 0, 11) === "hysteria://") {
        return "hysteria";
    }
}

function extractLinksByType($inputString, $configType)
{
    $pattern = "/(" . $configType . '):\/\/[^"\'\s]+/';
    preg_match_all($pattern, $inputString, $matches);

    if (empty($matches[0])) {
        return null;
    } else {
        return $matches[0];
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
                : "TVC" . getRandomName(),
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
        $name = isset($url["fragment"]) ? urldecode($url["fragment"]) : "TVC" . getRandomName();
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
            $url .= "#" . str_replace(" ", "%20", $configArray["name"]);
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
        $url .= "#" . str_replace(" ", "%20", $obj["hash"]);
    }
    return $url;
}

function is_reality($input)
{
    $type = detect_type($input);
    if (stripos($input, "reality") !== false && $type === "vless") {
        return true;
    }
    return false;
}

function isBase64($input)
{
    if (base64_encode(base64_decode($input)) === $input) {
        return true;
    }

    return false;
}

function getRandomName() {
    $alphabet = 'abcdefghijklmnopqrstuvwxyz';
    $name = '';
    for ($i = 0; $i < 10; $i++) {
      // Get a random letter from the alphabet
      $randomLetter = $alphabet[rand(0, strlen($alphabet) - 1)];
      // Add the letter to the name string
      $name .= $randomLetter;
    }
    return $name;
  }

function deleteFolder($folder) {
    if (!is_dir($folder)) {
        return;
    }
    $files = glob($folder . '/*');
    foreach ($files as $file) {
        is_dir($file) ? deleteFolder($file) : unlink($file);
    }
    rmdir($folder);
}

function tehran_time()
{
    date_default_timezone_set("Asia/Tehran");
    $tehran_time = time();
    $formatted_time = date("Y-m-d H:i:s", $tehran_time);

    return $formatted_time;
}

function hiddifyHeader ($subscriptionName) {
    return "#profile-title: base64:" . base64_encode($subscriptionName) . "
#profile-update-interval: 1
#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
#support-url: https://t.me/v2raycollector
#profile-web-page-url: https://github.com/yebekhe/TelegramV2rayCollector

";
}
