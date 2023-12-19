<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

// Fetch the JSON data from the API and decode it into an associative array
$sourcesArray = json_decode(
    file_get_contents("https://api.yebekhe.link/tvc-channels/channels.json"),
    true
);
deleteFolder("channelsData/logos");
deleteFolder("channelsData");
mkdir("channelsData");
mkdir("channelsData/logos");

foreach ($sourcesArray as $source => $types) {
    // Fetch the HTML content of the Telegram channel page
    $tempData = file_get_contents("https://t.me/s/" . $source);
    
    // Extract the title and image URL using regular expressions
    $title_pattern = '#<meta property="twitter:title" content="(.*?)">#';
    $image_pattern = '#<meta property="twitter:image" content="(.*?)">#';
    preg_match($image_pattern, $tempData , $image_match);
    preg_match($title_pattern, $tempData , $title_match);
    
    // Save the image file to local storage
    file_put_contents("channelsData/logos/" . $source . ".jpg", file_get_contents($image_match[1]));
    
    // Build the channel data array
    $channelArray[$source]['types'] = $types;
    $channelArray[$source]['title'] = $title_match[1];
    $channelArray[$source]['logo'] = "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/channelsData/logos/" . $source . ".jpg";
}

// Save the channel data array as JSON
file_put_contents("channelsData/channelsAssets.json", json_encode($channelArray , JSON_PRETTY_PRINT));

