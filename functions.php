<?php

function ptt($payload)
{
	global $pentesttools_apikey;
	$api_url = "https://pentest-tools.com/api?key=$pentesttools_apikey";
	$ch = curl_init($api_url);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
	curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	$json_data = curl_exec($ch);
	curl_close($ch);
	return $json_data;
}

function logger($message) {
	$ip = $_SERVER['REMOTE_ADDR'];
	$log  = date("Y-m-d H:i:s")." IP:$ip ".$message.PHP_EOL;
	file_put_contents('/opt/logs/freescan_'.date("j.n.Y").'.log', $log, FILE_APPEND);
}

function check_blacklist($target)
{
	global $blacklist;
	foreach ($blacklist as $url) {
		if (stripos($target, $url) !== FALSE) {
			return true;
		}
	}
}

function error_msg($subject, $error)
{
	echo "<div class=\"alert alert-danger\" role=\"alert\"><strong>$subject</strong><br /><br />$error</div>";
}

?>
