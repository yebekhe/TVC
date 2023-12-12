<?php

$subscriptionArrays = [];
$subscriptionFromFile = explode("\n", file_get_contents("subscriptions.txt"));

$subscriptionArrays = array_merge($subscriptionArrays, $subscriptionFromFile);
$output = "";

function isBase64($input)
{
    if (base64_encode(base64_decode($input)) === $input) {
        return true;
    }

    return false;
}

foreach ($subscriptionArrays as $subscription) {
if ($subscription !== "") {
$configsList = file_get_contents($subscription);
    if (isBase64($configsList)) {
        $output .= base64_decode($configsList) . "\n";
    } else {
        $output .= $configsList . "\n";
    }
}
}


file_put_contents("config.txt", $output);
echo $output;
