<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

function getRandomIp ($ipRange) {
    $ipArray = explode(".", $ipRange);
    $randNum = rand(0,255);
    unset($ipArray[3]);
    return implode(".", $ipArray) . "." . strval($randNum);
}

$ipRanges = [
    "162.159.192.0",
    "162.159.193.0",
    "162.159.195.0",
    "188.114.96.0",
    "188.114.97.0",
    "188.114.98.0",
    "188.114.99.0"
];

$ports = "500,854,859,864,878,880,890,891,894,903,908,928,934,939,942,943, 945,946,955,968,987,988,1002,1010,1014,1018,1070,1074,1180, 1387,1701,1843,2371,2408,2506,3138,3476,3581, 384,4177,4198,4233,4500,5279,5956,7103,7152, 7156,7281,7559,8319,8742,8854,8886";


$choosenRanges = [
    $ipRanges[rand(0,6)],
    $ipRanges[rand(0,6)]
];
$choosenIps = [
    getRandomIp($choosenRanges[0]),
    getRandomIp($choosenRanges[1])
];
$portsArray = explode(",", $ports);
$choosenPort = $portsArray[array_rand($portsArray)];

$profileConfigs = [
    "warp://" . $choosenIps[0] . ":" . $choosenPort . "?ifp=5-10#" . $choosenIps[0] . ":" . $choosenPort,
    "warp://" . $choosenIps[1] . ":" . $choosenPort . "?ifp=5-10#" . $choosenIps[1] . ":" . $choosenPort,
    "warp://" . $choosenIps[0] . ":" . $choosenPort . "?ifp=5-10#" . $choosenIps[0] . ":" . $choosenPort . "&&detour=warp://" . $choosenIps[1] . ":" . $choosenPort . "?ifp=5-10#" . $choosenIps[1] . ":" . $choosenPort,
    "warp://" . $choosenIps[1] . ":" . $choosenPort . "?ifp=5-10#" . $choosenIps[1] . ":" . $choosenPort . "&&detour=warp://" . $choosenIps[0] . ":" . $choosenPort . "?ifp=5-10#" . $choosenIps[0] . ":" . $choosenPort,
];

$profileHeader = "#profile-title: base64:" . base64_encode("TVC | WARP") . "
#profile-update-interval: 1
#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
#support-url: https://t.me/v2raycollector
#profile-web-page-url: https://github.com/yebekhe/TelegramV2rayCollector
";

$profileOutput = $profileHeader . "
" . implode("\n", $profileConfigs);

file_put_contents("subscriptions/warp/config", $profileOutput);

echo "\nWARP Configuration created!\n";
