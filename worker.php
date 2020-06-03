<?php

include('functions.php');

$target = argv[1];
$cip = argv[2];

// Send the scan job to webscan at Pentest Tools
$payload = "{\"op\":\"start_scan\",\"tool_id\":170,\"tool_params\":{\"target\":\"$target\",\"scan_type\":\"quick\",\"follow_redirects\":\"true\"}}";
$json_data = ptt($payload);
$json = json_decode($json_data);
$scan_id = $json->scan_id;
$scan_status = $json->scan_status;
logger("CIP:$cip TARGET:$target STATUS:$scan_status");
dblogger($cip,$target,$scan_status);

// If the scan is waiting, loop and keep checking it every 5 seconds
if ($scan_status = "waiting") {
    while ($scan_status == "waiting") {
        sleep(5);
        $payload = "{\"op\":\"get_scan_status\",\"scan_id\":$scan_id}";
        $json_data = ptt($payload);
        $json = json_decode($json_data);
        $scan_status = $json->scan_status;
        logger("CIP:$cip TARGET:$target STATUS:$scan_status");
        dblogger($cip,$target,$scan_status);
    }
}

// If the scan is running, loop and keep checking it every 5 seconds
if ($scan_status = "running") {
    while ($scan_status == "running") {
        sleep(5);
        $payload = "{\"op\":\"get_scan_status\",\"scan_id\":$scan_id}";
        $json_data = ptt($payload);
        $json = json_decode($json_data);
        $scan_status = $json->scan_status;
        logger("CIP:$cip TARGET:$target STATUS:$scan_status");
        dblogger($cip,$target,$scan_status);
    }
}

if ($scan_status == "finished") {
    // Get the scan output
    logger("CIP:$cip TARGET:$target STATUS:$scan_status");
    dblogger($cip,$target,$scan_status);
    $payload = "{\"op\":\"get_output\",\"scan_id\":$scan_id,\"output_format\":\"json\"}";
    $json = ptt($payload);
    $json_report_data = json_decode($json);

    // Delete the scan from Pentest Tools
    $payload = "{\"op\":\"delete_scan\",\"scan_id\":$scan_id}";
    ptt($payload);
    logger("CIP:$cip TARGET:$target STATUS:deleted");
    dblogger($cip,$target,"deleted");

    $high_count = $json_report_data->scan_info->output_summary->high;
    $medium_count = $json_report_data->scan_info->output_summary->medium;
    $low_count = $json_report_data->scan_info->output_summary->low;
    $info_count = $json_report_data->scan_info->output_summary->info;
    $start = $json_report_data->scan_info->start_time;
    $stop = $json_report_data->scan_info->end_time;
    $duration = $json_report_data->scan_info->duration;
    $num_tests = $json_report_data->scan_info->num_tests;
    $num_finished_tests = $json_report_data->scan_info->num_finished_tests;

    $arrayLength = count($json_report_data->scan_output->scan_tests);
    $i = 0;
    while ($i < $arrayLength) {
        $name = $json_report_data->scan_output->scan_tests[$i]->vuln_description;
        $description = $json_report_data->scan_output->scan_tests[$i]->risk_description;
        $vuln_evidence = $json_report_data->scan_output->scan_tests[$i]->vuln_evidence->data;
        $risklevel = $json_report_data->scan_output->scan_tests[$i]->risk_level;
        $evidence = '<tr>';
        if (is_array($vuln_evidence)) {
            $evidence_Length = count($vuln_evidence);
            $ecount = 0;
            while ($ecount < $evidence_Length) {
                if (ISSET($vuln_evidence[$ecount][0])) {
                    $vdata = str_replace("                 ", " ", $vuln_evidence[$ecount][0]);
                    $vdata = str_replace(" 						", " ", $vdata);
                    $vdata = preg_replace("/<img[^>]+>/i", "", $vdata);
                    $evidence .= "<td>$vdata</td>";
                }
                if (ISSET($vuln_evidence[$ecount][1])) {
                    $vdata = str_replace("                 ", " ", $vuln_evidence[$ecount][1]);
                    $vdata = str_replace("                                          ", " ", $vdata);
                    $vdata = preg_replace("/<img[^>]+>/i", "", $vdata);
                    $evidence .= "<td>$vdata</td>";
                }
                if (ISSET($vuln_evidence[$ecount][2])) {
                    $vdata = str_replace("                 ", " ", $vuln_evidence[$ecount][2]);
                    $vdata = str_replace("                                          ", " ", $vdata);
                    $evidence .= "<td>$vdata</td>";
                }
                if (ISSET($vuln_evidence[$ecount][3])) {
                    $vdata = str_replace("                 ", " ", $vuln_evidence[$ecount][3]);
                    $vdata = str_replace("                                          ", " ", $vdata);
                    $evidence .= "<td>$vdata</td>";
                }
                if (ISSET($vuln_evidence[$ecount][4])) {
                    $vdata = str_replace("                 ", " ", $vuln_evidence[$ecount][4]);
                    $vdata = str_replace("                                          ", " ", $vdata);
                    $evidence .= "<td>$vdata</td>";
                }
                if (ISSET($vuln_evidence[$ecount][5])) {
                    $vdata = str_replace("                 ", " ", $vuln_evidence[$ecount][5]);
                    $vdata = str_replace("                                          ", " ", $vdata);
                    $evidence .= "<td>$vdata</td>";
                }
                if (ISSET($vuln_evidence[$ecount][6])) {
                    $vdata = str_replace("                 ", " ", $vuln_evidence[$ecount][6]);
                    $vdata = str_replace("                                          ", " ", $vdata);
                    $evidence .= "<td>$vdata</td>";
                }
                if (ISSET($vuln_evidence[$ecount][7])) {
                    $vdata = str_replace("                 ", " ", $vuln_evidence[$ecount][7]);
                    $vdata = str_replace("                                          ", " ", $vdata);
                    $evidence .= "<td>$vdata</td>";
                }
                if (ISSET($vuln_evidence[$ecount][8])) {
                    $vdata = str_replace("                 ", " ", $vuln_evidence[$ecount][8]);
                    $vdata = str_replace("                                          ", " ", $vdata);
                    $evidence .= "<td>$vdata</td>";
                }
                $evidence .= "</tr>";
                $ecount++;
            }
        } else {
            if (EMPTY($evidence)) {
                $evidence = "No evidence was collected for this vulnerability";
            }
        }
        $recommendation = $json_report_data->scan_output->scan_tests[$i]->recommendation;


        $sql = "INSERT INTO vulnerabilities (cip,target,vulnName,vulnRiskLevel,vulnEvidence,vulnDescription,vulnRecommendation) VALUES ('$cip','$target','$name','$risklevel','$evidence','$description','$recommendation')";
        $i++;
    }

    $sql = "INSERT INTO W (cip,target,start,stop,duration,num_tests,num_finished_tests) VALUES ('$cip','$target','$start','$stop','$duration','$num_tests','$num_finished_tests')";


}
