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
function getCipher($decodedConfig)
{
    return isset($decodedConfig["scy"]) ? $decodedConfig["scy"] : "auto";
}

function getUUID($decodedConfig)
{
    if (is_valid_uuid($decodedConfig["id"]) === false) {
        return null;
    }
    return str_replace(" ", "+", $decodedConfig["id"]);
}

function getVMessTLS($decodedConfig)
{
    return $decodedConfig["tls"] === "tls" ? true : false;
}

function vmessToClash($input)
{
    $decodedConfig = configParse($input);
    if (is_null(getUUID($decodedConfig))) {
        return null;
    }
    $vmessTemplate = [
        "name" => urldecode($decodedConfig["ps"]),
        "type" => "vmess",
        "server" => $decodedConfig["add"],
        "port" => $decodedConfig["port"],
        "cipher" => getCipher($decodedConfig),
        "uuid" => getUUID($decodedConfig),
        "alterId" => $decodedConfig["aid"] ?? "0",
        "tls" => getVMessTLS($decodedConfig),
        "skip-cert-verify" => true,
        "network" => $decodedConfig["net"] ?? "tcp",
    ];

    if ($vmessTemplate["network"] === "ws") {
        $vmessTemplate["ws-opts"] = [
            "path" => processWsPath($decodedConfig["path"])["path"],
            "headers" => [
                "host" => $decodedConfig["host"] ?? $decodedConfig["add"],
            ],
        ];
    } elseif ($vmessTemplate["network"] === "grpc") {
        $servicename = htmlentities($decodedConfig["path"], ENT_QUOTES);
        $vmessTemplate["grpc-opts"] = [
            "grpc-service-name" => $servicename,
            "grpc-mode" => $decodedConfig["type"],
        ];
        $vmessTemplate["tls"] = true;
    }

    return "  - " . json_encode($vmessTemplate, JSON_UNESCAPED_UNICODE);
}

function vmessToSurfboard($input)
{
    $decodedConfig = configParse($input);
    if (is_null(getUUID($decodedConfig))) {
        return null;
    }
    $networkType = isset($decodedConfig["net"]) ? $decodedConfig["net"] : "tcp";
    $alterId = isset($decodedConfig["aid"]) ? $decodedConfig["aid"] : "0";
    $AEAD = $alterId === "0" ? "true" : "false";
    if ($networkType === "ws") {
        $vmessTemplate =
        urldecode($decodedConfig["ps"]) .
            " = vmess, " .
            $decodedConfig["add"] .
            ", " .
            $decodedConfig["port"] .
            ", username = " .
            getUUID($decodedConfig) .
            ", ws = true, tls = " .
            getVMessTLS($decodedConfig) .
            ", vmess-aead = " .
            $AEAD .
            ", ws-path = " .
            htmlentities($decodedConfig["path"], ENT_QUOTES) .
            ', ws-headers = Host:"' .
            $decodedConfig["host"] .
            '", skip-cert-verify = true, tfo = false';
    }
    return $vmessTemplate;
}

function trojanToClash($input)
{
    $decodedConfig = configParse($input);
    $trojanTemplate = [
        "name" => urldecode($decodedConfig["hash"]),
        "type" => "trojan",
        "server" => $decodedConfig["hostname"],
        "port" => $decodedConfig["port"],
        "udp" => false,
        "password" => $decodedConfig["username"],
        "skip-cert-verify" =>
            isset($decodedConfig["params"]["allowInsecure"]) &&
            $decodedConfig["params"]["allowInsecure"] === "1"
                ? true
                : false,
        "network" => "tcp",
        "client-fingerprint" => "chrome",
    ];
    if (isset($decodedConfig["params"]["sni"])) {
        $trojanTemplate["sni"] = $decodedConfig["params"]["sni"];
    }
    return "  - " . json_encode($trojanTemplate, JSON_UNESCAPED_UNICODE);
}

function trojanToSurfboard($input)
{
    $decodedConfig = configParse($input);
    $skipCertVerify =
        isset($decodedConfig["params"]["allowInsecure"]) &&
        $decodedConfig["params"]["allowInsecure"] === "1"
            ? "true"
            : "false";
    if (isset($decodedConfig["params"]["sni"])) {
        $trojanSni = ", sni = " . $decodedConfig["params"]["sni"];
    } else {
        $trojanSni = "";
    }
    $trojanTemplate =
    urldecode($decodedConfig["hash"]) .
        " = trojan, " .
        $decodedConfig["hostname"] .
        ", " .
        $decodedConfig["port"] .
        ", password = " .
        $decodedConfig["username"] .
        ", udp-delay = true, skip-cert-verify = " .
        $skipCertVerify .
        $trojanSni .
        ", ws = false";

    return $trojanTemplate;
}

function ssToClash($input)
{
    $decodedConfig = configParse($input);
    if (!is_string($decodedConfig["password"])) {
        return null;
    }
    $encryptionMethodes = [
        "chacha20-ietf-poly1305",
        "aes-256-gcm"
    ];
    if (!in_array($decodedConfig["encryption_method"], $encryptionMethodes)) {
        return null;
    }

    $shadowsocksTemplate = [
        "name" => urldecode($decodedConfig["name"]),
        "type" => "ss",
        "server" => $decodedConfig["server_address"],
        "port" => $decodedConfig["server_port"],
        "password" => $decodedConfig["password"],
        "cipher" => $decodedConfig["encryption_method"],
    ];
    return "  - " . json_encode($shadowsocksTemplate, JSON_UNESCAPED_UNICODE);
}

function ssToSurfboard($input)
{
    $decodedConfig = configParse($input);
    if ($decodedConfig["encryption_method"] === "2022-blake3-aes-256-gcm") {
        return null;
    }
    $encryptionMethodes = [
        "chacha20-ietf-poly1305",
        "aes-256-gcm"
    ];
    if (!in_array($decodedConfig["encryption_method"], $encryptionMethodes)) {
        return null;
    }
    $shadowsocksTemplate =
    urldecode($decodedConfig["name"]) .
        " = ss, " .
        $decodedConfig["server_address"] .
        ", " .
        $decodedConfig["server_port"] .
        ", encrypt-method = " .
        $decodedConfig["encryption_method"] .
        ", password = " .
        $decodedConfig["password"];
    return $shadowsocksTemplate;
}

function is_valid_uuid($uuid_string)
{
    $pattern =
        '/^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$/i';
    return (bool) preg_match($pattern, $uuid_string);
}

function getPort($decodedConfig)
{
    return isset($decodedConfig["port"]) && $decodedConfig["port"] !== ""
        ? $decodedConfig["port"]
        : 443;
}

function getTls($decodedConfig)
{
    return isset($decodedConfig["params"]["security"]) &&
        $decodedConfig["params"]["security"] === "tls"
        ? true
        : false;
}

function getNetwork($decodedConfig)
{
    return isset($decodedConfig["params"]["type"])
        ? $decodedConfig["params"]["type"]
        : "tcp";
}

function getUsername($decodedConfig)
{
    if (is_valid_uuid($decodedConfig["username"]) === false) {
        return null;
    }
    return $decodedConfig["username"];
}

function vlessToMeta($input)
{
    $decodedConfig = configParse($input);
    if (is_null(getUsername($decodedConfig))) {
        return null;
    }

    $vlessTemplate = [
        "name" => urldecode($decodedConfig["hash"]),
        "type" => "vless",
        "server" => $decodedConfig["hostname"],
        "port" => getPort($decodedConfig),
        "udp" => false,
        "uuid" => getUsername($decodedConfig),
        "tls" => getTls($decodedConfig),
        "network" => getNetwork($decodedConfig),
        "client-fingerprint" => "chrome",
    ];
    if (isset($decodedConfig["params"]["sni"])) {
        $vlessTemplate["servername"] = $decodedConfig["params"]["sni"];
    }
    if (isset($decodedConfig["params"]["flow"])) {
        $vlessTemplate["flow"] = "xtls-rprx-vision";
    }
    if ($vlessTemplate["network"] === "ws") {
        $path = isset($decodedConfig["params"]["path"])
            ? htmlentities($decodedConfig["params"]["path"], ENT_QUOTES)
            : "/";
        $vlessTemplate["ws-opts"] = [
            "path" => $path,
        ];
        if (isset($decodedConfig["params"]["host"])) {
            $vlessTemplate["ws-opts"]["headers"] = [
                "host" => $decodedConfig["params"]["host"],
            ];
        }
    } elseif (
        $vlessTemplate["network"] === "grpc" &&
        isset($decodedConfig["params"]["serviceName"])
    ) {
        $vlessTemplate["grpc-opts"] = [
            "grpc-service-name" => $decodedConfig["params"]["serviceName"],
        ];
        $vlessTemplate["tls"] = true;
    }
    if (
        !is_null($decodedConfig["params"]["security"]) &&
        $decodedConfig["params"]["security"] === "reality"
    ) {
        $vlessTemplate["udp"] = true;
        $vlessTemplate["tls"] = true;
        $vlessTemplate["client-fingerprint"] = $decodedConfig["params"]["fp"];
        $contaminatedFp = ["android", "ios", "random"];
        if (
            in_array(
                strtolower($decodedConfig["params"]["fp"]),
                $contaminatedFp
            )
        ) {
            return null;
        }
        $vlessTemplate["reality-opts"] = [
            "public-key" => $decodedConfig["params"]["pbk"],
        ];
        if (
            !is_null($decodedConfig["params"]["sid"]) &&
            $decodedConfig["params"]["sid"] !== ""
        ) {
            $vlessTemplate["reality-opts"]["short-id"] =
                $decodedConfig["params"]["sid"];
        }
    }
    return "  - " . json_encode($vlessTemplate, JSON_UNESCAPED_UNICODE);
}

function toClashSurfboard($input, $outboundType)
{
    $configType = detect_type($input);
    if (
        $configType === "vless" &&
        in_array($outboundType, ["clash", "surfboard"])
    ) {
        return null;
    }
    if (!in_array($configType, ["vmess", "vless", "trojan", "ss"])) {
        return null;
    }
    $functionsArray = [
        "vmess" => [
            "clash" => "vmessToClash",
            "meta" => "vmessToClash",
            "surfboard" => "vmessToSurfboard",
        ],
        "vless" => [
            "meta" => "vlessToMeta",
        ],
        "trojan" => [
            "clash" => "trojanToClash",
            "meta" => "trojanToClash",
            "surfboard" => "trojanToSurfboard",
        ],
        "ss" => [
            "clash" => "ssToClash",
            "meta" => "ssToClash",
            "surfboard" => "ssToSurfboard",
        ],
    ];
    
    return $functionsArray[$configType][$outboundType]($input);
}

function configsHeader($outboundType, $surfboardUrl = "")
{
    return [
        "clash" => [
            "mixed-port: 7890",
            "allow-lan: true",
            "tcp-concurrent: true",
            "enable-process: true",
            "find-process-mode: always",
            "mode: rule",
            "log-level: error",
            "ipv6: true",
            "external-controller: 127.0.0.1:9090",
            "experimental:",
            "  ignore-resolve-fail: true",
            "  sniff-tls-sni: true",
            "  tracing: true",
            "hosts:",
            '  "localhost": 127.0.0.1',
            "profile:",
            "  store-selected: true",
            "  store-fake-ip: true",
            "",
            "sniffer:",
            "  enable: true",
            "  sniff:",
            "    http: { ports: [1-442, 444-8442, 8444-65535], override-destination: true }",
            "    tls: { ports: [1-79, 81-8079, 8081-65535], override-destination: true }",
            "  force-domain:",
            '      - "+.v2ex.com"',
            "      - www.google.com",
            "      - google.com",
            "  skip-domain:",
            "      - Mijia Cloud",
            "      - dlg.io.mi.com",
            "  sniffing:",
            "    - tls",
            "    - http",
            "  port-whitelist:",
            '    - "80"',
            '    - "443"',
            "",
            "tun:",
            "  enable: true",
            "  prefer-h3: true",
            "  listen: 0.0.0.0:53",
            "  stack: gvisor",
            "  dns-hijack:",
            '     - "any:53"',
            '     - "tcp://any:53"',
            "  auto-redir: true",
            "  auto-route: true",
            "  auto-detect-interface: true",
            "",
            "dns:",
            "  enable: true",
            "  ipv6: true",
            "  default-nameserver:",
            "    - '1.1.1.1'",
            "    - '8.8.8.8'",
            "  enhanced-mode: fake-ip",
            "  fake-ip-range: 198.18.0.1/16",
            "  fake-ip-filter:",
            "    - 'stun.*.*'",
            "    - 'stun.*.*.*'",
            "    - '+.stun.*.*'",
            "    - '+.stun.*.*.*'",
            "    - '+.stun.*.*.*.*'",
            "    - '+.stun.*.*.*.*.*'",
            "    - '*.lan'",
            "    - '+.msftncsi.com'",
            "    - msftconnecttest.com",
            "    - 'time?.*.com'",
            "    - 'time.*.com'",
            "    - 'time.*.gov'",
            "    - 'time.*.apple.com'",
            "    - time-ios.apple.com",
            "    - 'time1.*.com'",
            "    - 'time2.*.com'",
            "    - 'time3.*.com'",
            "    - 'time4.*.com'",
            "    - 'time5.*.com'",
            "    - 'time6.*.com'",
            "    - 'time7.*.com'",
            "    - 'ntp?.*.com'",
            "    - 'ntp.*.com'",
            "    - 'ntp1.*.com'",
            "    - 'ntp2.*.com'",
            "    - 'ntp3.*.com'",
            "    - 'ntp4.*.com'",
            "    - 'ntp5.*.com'",
            "    - 'ntp6.*.com'",
            "    - 'ntp7.*.com'",
            "    - '+.pool.ntp.org'",
            "    - '+.ipv6.microsoft.com'",
            "    - speedtest.cros.wr.pvp.net",
            "    - network-test.debian.org",
            "    - detectportal.firefox.com",
            "    - cable.auth.com",
            "    - miwifi.com",
            "    - routerlogin.com",
            "    - routerlogin.net",
            "    - tendawifi.com",
            "    - tendawifi.net",
            "    - tplinklogin.net",
            "    - tplinkwifi.net",
            "    - '*.xiami.com'",
            "    - tplinkrepeater.net",
            "    - router.asus.com",
            "    - '*.*.*.srv.nintendo.net'",
            "    - '*.*.stun.playstation.net'",
            "    - '*.openwrt.pool.ntp.org'",
            "    - resolver1.opendns.com",
            "    - 'GC._msDCS.*.*'",
            "    - 'DC._msDCS.*.*'",
            "    - 'PDC._msDCS.*.*'",
            "  use-hosts: true",
            "  nameserver:",
            "    - '8.8.4.4'",
            "    - '1.0.0.1'",
            '    - "https://1.0.0.1/dns-query"',
            '    - "https://8.8.4.4/dns-query"',
            "",
        ],
        "meta" => [
            "mixed-port: 7890",
            "allow-lan: true",
            "tcp-concurrent: true",
            "enable-process: true",
            "find-process-mode: always",
            "mode: rule",
            "log-level: error",
            "ipv6: true",
            "external-controller: 127.0.0.1:9090",
            "experimental:",
            "  ignore-resolve-fail: true",
            "  sniff-tls-sni: true",
            "  tracing: true",
            "hosts:",
            '  "localhost": 127.0.0.1',
            "profile:",
            "  store-selected: true",
            "  store-fake-ip: true",
            "",
            "sniffer:",
            "  enable: true",
            "  sniff:",
            "    http: { ports: [1-442, 444-8442, 8444-65535], override-destination: true }",
            "    tls: { ports: [1-79, 81-8079, 8081-65535], override-destination: true }",
            "  force-domain:",
            '      - "+.v2ex.com"',
            "      - www.google.com",
            "      - google.com",
            "  skip-domain:",
            "      - Mijia Cloud",
            "      - dlg.io.mi.com",
            "  sniffing:",
            "    - tls",
            "    - http",
            "  port-whitelist:",
            '    - "80"',
            '    - "443"',
            "",
            "tun:",
            "  enable: true",
            "  prefer-h3: true",
            "  listen: 0.0.0.0:53",
            "  stack: gvisor",
            "  dns-hijack:",
            '     - "any:53"',
            '     - "tcp://any:53"',
            "  auto-redir: true",
            "  auto-route: true",
            "  auto-detect-interface: true",
            "",
            "dns:",
            "  enable: true",
            "  ipv6: true",
            "  default-nameserver:",
            "    - '1.1.1.1'",
            "    - '8.8.8.8'",
            "  enhanced-mode: fake-ip",
            "  fake-ip-range: 198.18.0.1/16",
            "  fake-ip-filter:",
            "    - 'stun.*.*'",
            "    - 'stun.*.*.*'",
            "    - '+.stun.*.*'",
            "    - '+.stun.*.*.*'",
            "    - '+.stun.*.*.*.*'",
            "    - '+.stun.*.*.*.*.*'",
            "    - '*.lan'",
            "    - '+.msftncsi.com'",
            "    - msftconnecttest.com",
            "    - 'time?.*.com'",
            "    - 'time.*.com'",
            "    - 'time.*.gov'",
            "    - 'time.*.apple.com'",
            "    - time-ios.apple.com",
            "    - 'time1.*.com'",
            "    - 'time2.*.com'",
            "    - 'time3.*.com'",
            "    - 'time4.*.com'",
            "    - 'time5.*.com'",
            "    - 'time6.*.com'",
            "    - 'time7.*.com'",
            "    - 'ntp?.*.com'",
            "    - 'ntp.*.com'",
            "    - 'ntp1.*.com'",
            "    - 'ntp2.*.com'",
            "    - 'ntp3.*.com'",
            "    - 'ntp4.*.com'",
            "    - 'ntp5.*.com'",
            "    - 'ntp6.*.com'",
            "    - 'ntp7.*.com'",
            "    - '+.pool.ntp.org'",
            "    - '+.ipv6.microsoft.com'",
            "    - speedtest.cros.wr.pvp.net",
            "    - network-test.debian.org",
            "    - detectportal.firefox.com",
            "    - cable.auth.com",
            "    - miwifi.com",
            "    - routerlogin.com",
            "    - routerlogin.net",
            "    - tendawifi.com",
            "    - tendawifi.net",
            "    - tplinklogin.net",
            "    - tplinkwifi.net",
            "    - '*.xiami.com'",
            "    - tplinkrepeater.net",
            "    - router.asus.com",
            "    - '*.*.*.srv.nintendo.net'",
            "    - '*.*.stun.playstation.net'",
            "    - '*.openwrt.pool.ntp.org'",
            "    - resolver1.opendns.com",
            "    - 'GC._msDCS.*.*'",
            "    - 'DC._msDCS.*.*'",
            "    - 'PDC._msDCS.*.*'",
            "  use-hosts: true",
            "  nameserver:",
            "    - '8.8.4.4'",
            "    - '1.0.0.1'",
            "    - \"https://1.0.0.1/dns-query\"",
            "    - \"https://8.8.4.4/dns-query\"",
            "  nameserver-policy:",
            "    'RULE-SET:ir,ircidr,geoip:ir,+.ir,+.bonyan.co': [\"217.218.155.155\", \"217.218.127.127\", \"https://dns.403.online/dns-query\", \"https://dns.shecan.ir/dns-query\"]",
            "",
        ],
        "surfboard" => [
            "#!MANAGED-CONFIG " . $surfboardUrl . " interval=60 strict=false",
            "",
            "[General]",
            "loglevel = notify",
            "interface = 127.0.0.1",
            "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local",
            "ipv6 = true",
            "dns-server = system, 223.5.5.5",
            "exclude-simple-hostnames = true",
            "enhanced-mode-by-rule = true",
        ],
    ][$outboundType];
}

function configsProxyGroup($outboundType)
{
    return [
        "clash" => [
            "proxy-groups:" => [
                "MANUAL" => [
                    "  - name: MANUAL",
                    "    type: select",
                    "    proxies:",
                    "      - URL-TEST",
                    "      - FALLBACK",
                ],
                "URL-TEST" => [
                    "  - name: URL-TEST",
                    "    type: url-test",
                    "    url: http://www.gstatic.com/generate_204",
                    "    interval: 60",
                    "    tolerance: 50",
                    "    proxies:",
                ],
                "FALLBACK" => [
                    "  - name: FALLBACK",
                    "    type: fallback",
                    "    url: http://www.gstatic.com/generate_204",
                    "    interval: 60",
                    "    proxies:",
                ],
            ],
        ],
        "meta" => [
            "proxy-groups:" => [
                "MANUAL" => [
                    "  - name: MANUAL",
                    "    type: select",
                    "    proxies:",
                    "      - URL-TEST",
                    "      - FALLBACK",
                ],
                "URL-TEST" => [
                    "  - name: URL-TEST",
                    "    type: url-test",
                    "    url: http://www.gstatic.com/generate_204",
                    "    interval: 60",
                    "    tolerance: 50",
                    "    proxies:",
                ],
                "FALLBACK" => [
                    "  - name: FALLBACK",
                    "    type: fallback",
                    "    url: http://www.gstatic.com/generate_204",
                    "    interval: 60",
                    "    proxies:",
                ],
            ],
        ],
        "surfboard" => [
            "[Proxy Group]" => [
                "MANUAL = select,URL-TEST,FALLBACK,",
                "URL-TEST = url-test,",
                "FALLBACK = fallback,",
            ],
        ],
    ][$outboundType];
}

function configsProxyRules($outboundType)
{
    return [
        "clash" => [
            "rules:",
            "  - IP-CIDR,127.0.0.1/32,DIRECT,no-resolve",
            "  - IP-CIDR,198.18.0.1/16,DIRECT,no-resolve",
            "  - IP-CIDR,28.0.0.1/8,DIRECT,no-resolve",
            "  - IP-CIDR6,::1/128,DIRECT,no-resolve",
            "  - DOMAIN-SUFFIX,local,DIRECT",
            "  - DOMAIN-SUFFIX,ip6-localhost,DIRECT",
            "  - DOMAIN-SUFFIX,ip6-loopback,DIRECT",
            "  - DOMAIN-SUFFIX,lan,DIRECT",
            "  - DOMAIN-SUFFIX,localhost,DIRECT",
            "  - DOMAIN-SUFFIX,ir,DIRECT",
            "  - DOMAIN,clash.razord.top,DIRECT",
            "  - DOMAIN,yacd.haishan.me,DIRECT",
            "  - DOMAIN,yacd.metacubex.one,DIRECT",
            "  - DOMAIN,clash.metacubex.one,DIRECT",
            "  - MATCH,MANUAL",
        ],
        "meta" => [
            "rule-providers:",
            "  ir: {type: http, format: text, behavior: domain, path: ./ruleset/ir.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ir.txt, interval: 86400}",
            "  ads: {type: http, format: text, behavior: domain, path: ./ruleset/ads.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ads.txt, interval: 86400}",
            "  ircidr: {type: http, format: text, behavior: ipcidr, path: ./ruleset/ircidr.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ircidr.txt, interval: 86400}",
            "  private: {type: http, format: text, behavior: ipcidr, path: ./ruleset/private.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/private.txt, interval: 86400}",
            "  apps: {type: http, format: text, behavior: domain, path: ./ruleset/apps.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/apps.txt, interval: 86400}",
            "  malware: {type: http, format: text, behavior: domain, path: ./ruleset/malware.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/malware.txt, interval: 86400}",
            "  phishing: {type: http, format: text, behavior: domain, path: ./ruleset/phishing.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/phishing.txt, interval: 86400}",
            "  cryptominers: {type: http, format: text, behavior: domain, path: ./ruleset/cryptominers.txt, url: https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/cryptominers.txt, interval: 86400}",
            "rules:",
            "  - IP-CIDR,127.0.0.1/32,DIRECT,no-resolve",
            "  - IP-CIDR,198.18.0.1/16,DIRECT,no-resolve",
            "  - IP-CIDR,28.0.0.1/8,DIRECT,no-resolve",
            "  - IP-CIDR6,::1/128,DIRECT,no-resolve",
            "  - DOMAIN-SUFFIX,local,DIRECT",
            "  - DOMAIN-SUFFIX,ip6-localhost,DIRECT",
            "  - DOMAIN-SUFFIX,ip6-loopback,DIRECT",
            "  - DOMAIN-SUFFIX,lan,DIRECT",
            "  - DOMAIN-SUFFIX,localhost,DIRECT",
            "  - DOMAIN-SUFFIX,ir,DIRECT",
            "  - DOMAIN,clash.razord.top,DIRECT",
            "  - DOMAIN,yacd.haishan.me,DIRECT",
            "  - DOMAIN,yacd.metacubex.one,DIRECT",
            "  - DOMAIN,clash.metacubex.one,DIRECT",
            "  - RULE-SET,ads,REJECT",
            "  - RULE-SET,malware,REJECT",
            "  - RULE-SET,phishing,REJECT",
            "  - RULE-SET,cryptominers,REJECT",
            "  - RULE-SET,private,DIRECT",
            "  - RULE-SET,apps,DIRECT",
            "  - RULE-SET,ir,DIRECT",
            "  - RULE-SET,ircidr,DIRECT",
            "  - MATCH,MANUAL",
        ],
        "surfboard" => ["[Rule]", "GEOIP,IR,DIRECT", "FINAL,MANUAL"],
    ][$outboundType];
}

function reprocess($input)
{
    $input = str_replace("  - ", "", $input);
    $proxies_array = explode("\n", $input);
    foreach ($proxies_array as $proxy_json) {
        $proxy_array = json_decode($proxy_json, true);

        $output[] =
            "  - " .
            json_encode(
                $proxy_array,
                JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
            );
    }
    return str_replace("  - null", "", implode("\n", $output));
}

function fullConfigGenerator(
    $configsHeader,
    $proxies,
    $configsProxyGroup,
    $configsProxyRules,
    $configsName,
    $outboundType
) {
    $configHeader = implode("\n", $configsHeader);
    if (in_array($outboundType, ["clash", "meta"])) {
        $proxies = "proxies:\n" . $proxies;
        $proxiesGroupString = "proxy-groups:";
        $proxiesGroupManual =
            implode("\n", $configsProxyGroup["proxy-groups:"]["MANUAL"]) .
            "\n" .
            $configsName;
        $proxiesGroupUrltest =
            implode("\n", $configsProxyGroup["proxy-groups:"]["URL-TEST"]) .
            "\n" .
            $configsName;
        $proxiesGroupFallback =
            implode("\n", $configsProxyGroup["proxy-groups:"]["FALLBACK"]) .
            "\n" .
            $configsName;
    } elseif ($outboundType === "surfboard") {
        $proxies = "\n[Proxy]\nDIRECT = direct\n" . $proxies;
        $proxiesGroupString = "[Proxy Group]";
        $proxiesGroupManual = str_replace(
            ",,",
            "",
            $configsProxyGroup["[Proxy Group]"][0] . $configsName . "\n"
        );
        $proxiesGroupUrltest = str_replace(
            ",,",
            "",
            $configsProxyGroup["[Proxy Group]"][1] . $configsName . "\n"
        );
        $proxiesGroupFallback = str_replace(
            ",,",
            "",
            $configsProxyGroup["[Proxy Group]"][2] . $configsName . "\n"
        );
    }

    $proxiesGroupString .=
        "\n" .
        $proxiesGroupManual .
        $proxiesGroupUrltest .
        $proxiesGroupFallback;
    $proxiesRules = implode("\n", $configsProxyRules);
    $output =
        $configHeader . "\n" . $proxies . $proxiesGroupString . $proxiesRules;
    return $output;
}

function extractNames($input, $outputType)
{
    $configsArray = explode("\n", $input);
    $configsName = "";
    if (in_array($outputType, ["clash", "meta"])) {
        $pattern = '/"name":"(.*?)"/';
        foreach ($configsArray as $config) {
            if (preg_match($pattern, $config, $matches)) {
                $configsName .= "      - '" . $matches[1] . "'\n";
            }
        }
    } elseif ($outputType === "surfboard") {
        foreach ($configsArray as $config) {
            $configSplit = explode(" = ", $config);
            $configsName .= $configSplit[0] . ",";
        }
    } else {
        $configsName = null;
    }
    return $configsName;
}

function processConvertion($base64ConfigsList, $outboundType, $surfboardUrl = '')
{
    $configsArray = explode("\n", base64_decode($base64ConfigsList));
    $proxies = "";
    foreach ($configsArray as $config) {
        $toClashSurfboard = toClashSurfboard($config, $outboundType);
        if (!is_null($toClashSurfboard) && $toClashSurfboard !== "  - ") {
            $proxies .= $toClashSurfboard . "\n";
        }
    }
    $configsName = extractNames($proxies, $outboundType);
    $configsHeader = configsHeader($outboundType, $surfboardUrl);
    $configsProxyGroup = configsProxyGroup($outboundType);
    $configsProxyRules = configsProxyRules($outboundType);

    $fullConfig = fullConfigGenerator(
        $configsHeader,
        $proxies,
        $configsProxyGroup,
        $configsProxyRules,
        $configsName,
        $outboundType
    );
    return $fullConfig;
}

$directoryOfFiles = [
    "subscriptions/xray/base64/mix",
    "subscriptions/xray/base64/vmess",
    "subscriptions/xray/base64/vless",
    "subscriptions/xray/base64/reality",
    "subscriptions/xray/base64/trojan",
    "subscriptions/xray/base64/ss",
];

foreach ($directoryOfFiles as $directory) {
    $configsData = file_get_contents($directory);
    $outputTypes = [
        "clash" => ["mix", "vmess", "trojan", "ss"],
        "meta" => ["mix", "vmess", "vless", "reality", "trojan", "ss"],
        "surfboard" => ["mix", "vmess", "trojan", "ss"],
    ];
    $configsType = explode("/", $directory)[3];
    foreach ($outputTypes as $outputType => $configsTypeArray) {
        if (in_array($configsType, $configsTypeArray)) {
            $surfboardUrl = $outboundType === "surfboard" ? 'https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/surfboard/' . $configsType : "";
            file_put_contents(
                "subscriptions/" .
                    $outputType .
                    "/" .
                    explode("/", $directory)[3],
                str_replace(
                    "\\",
                    "",
                    processConvertion($configsData, $outputType, $surfboardUrl)
                )
            );
        }
    }
}

echo "Convertion To Clash, Meta and Surfboard Done!\n";
