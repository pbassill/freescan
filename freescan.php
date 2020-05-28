<?php

/*
 * Plugin Name: Secure GI Free Scan
 * Plugin URI:  https://www.hedgehogsecurity.gi/secure-gi
 * Description: Secure GI - free website vulnerability scanner
 * Version:     1.0.01
 * Author:      Peter Bassill
 * Author URI:  https://peterbassill.com
 * License:     Commercial
 * License URI: https://peterbassill.com/secure-gi
 *
 * */

include('functions.php');

function ptt($payload)
{
    $pentesttools_apikey = "9525c4535b9c1b22b39fecef501551e4e5cf89ac";
    $api_url = "https://pentest-tools.com/api?key=$pentesttools_apikey";
    $ch = curl_init($api_url);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $json_data = curl_exec($ch);
    curl_close($ch);
    return $json_data;
}

function freescan()
{
    if (ISSET($_POST['submit'])) {
        $target = $_POST['url'];

        // Lets do some sanitization on the target
        // Check for trailing / and remove it
        $target = rtrim($target, "/");

        // Send the scan job to webscan at Pentest Tools
        $payload = "{\"op\":\"start_scan\",\"tool_id\":170,\"tool_params\":{\"target\":\"$target\",\"scan_type\":\"quick\",\"follow_redirects\":\"true\"}}";
        $json_data = ptt($payload);
        $json = json_decode($json_data);
        $scan_id = $json->scan_id;
        $scan_status = $json->scan_status;

        // If the scan is waiting, loop and keep checking it every 5 seconds
        if ($scan_status = "waiting") {
            while ($scan_status == "waiting") {
                sleep(5);
                $payload = "{\"op\":\"get_scan_status\",\"scan_id\":$scan_id}";
                $json_data = ptt($payload);
                $json = json_decode($json_data);
                $scan_status = $json->scan_status;
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
            }
        }

        if ($scan_status == "finished") {
            // Get the scan output
            $payload = "{\"op\":\"get_output\",\"scan_id\":$scan_id,\"output_format\":\"json\"}";
            $json = ptt($payload);
            $json_report_data = json_decode($json);

            // Delete the scan from Pentest Tools
            $payload = "{\"op\":\"delete_scan\",\"scan_id\":$scan_id}";
            $json_data = ptt($payload);

            // Format the output JSON into a nice report
            echo "<h3>Scan Report</h3>";
            echo "<h4>Website vulnerability scan report for: $target</h4>";

            $high_count = $json_report_data->scan_info->output_summary->high;
            $medium_count = $json_report_data->scan_info->output_summary->medium;
            $low_count = $json_report_data->scan_info->output_summary->low;
            $info_count = $json_report_data->scan_info->output_summary->info;

            echo "<h5>Overall Risk Level: ";
            if($high_count >= '1') { echo "<button type=\"button\" class=\"btn btn-danger\">High</button>"; }
            elseif($medium_count >= '1') { echo "<button type=\"button\" class=\"btn btn-warning\">Medium</button>"; }
            elseif($low_count >= '1') { echo "<button type=\"button\" class=\"btn btn-success\">Low</button>"; }
            else { echo "<button type=\"button\" class=\"btn btn-info\">Zero</button>"; }

            echo "<p>&nbsp;</p>";
            echo "<h5>Vulnerability Summary</h5>";
            echo "<table class=\"table table-striped table-bordered\" width=\"100%\">";
            echo "<thead><tr><th>Criticality</th><th>Count</th></tr></thead>";
            echo "<body><tr><td>High</td><td>$high_count</td></tr>";
            echo "<tr><td>Medium</td><td>$medium_count</td></tr>";
            echo "<tr><td>Low</td><td>$low_count</td></tr>";
            echo "<tr><td>Informational</td><td>$info_count</td></tr></tbody></table>";
            echo "<p>&nbsp;</p>";

            $start = $json_report_data->scan_info->start_time;
            $stop = $json_report_data->scan_info->end_time;
            $duration = $json_report_data->scan_info->duration;
            $num_tests = $json_report_data->scan_info->num_tests;
            $num_finished_tests = $json_report_data->scan_info->num_finished_tests;


            echo "<h4>Findings</h4>";
            $arrayLength = count($json_report_data->scan_output->scan_tests);
            $i = 0;
            while ($i < $arrayLength)
            {
                $name = $json_report_data->scan_output->scan_tests[$i]->vuln_description;
                $description = $json_report_data->scan_output->scan_tests[$i]->risk_description;
                $cve = $json_report_data->scan_output->scan_tests[$i]->cve;
                $cvss = $json_report_data->scan_output->scan_tests[$i]->cvss;
                $cvssvector = '';
                $vuln_evidence = $json_report_data->scan_output->scan_tests[$i]->vuln_evidence->data;
                $risklevel = $json_report_data->scan_output->scan_tests[$i]->risk_level;
                if($risklevel == "0") { $severity = "<button type=\"button\" class=\"btn btn-info btn-sm\">Informational</button>"; }
                if($risklevel == "1") { $severity = "<button type=\"button\" class=\"btn btn-success btn-sm\">Low</button>"; }
                if($risklevel == "2") { $severity = "<button type=\"button\" class=\"btn btn-warning btn-sm\">Medium</button>"; }
                if($risklevel == "3") { $severity = "<button type=\"button\" class=\"btn btn-danger btn-sm\">High</button>"; }
                $status = $json_report_data->scan_output->scan_tests[$i]->status;
                $evidence = '<tr>';
                if (is_array($vuln_evidence)){
                    $evidence_Length = count($vuln_evidence);
                    $ecount = 0;
                    while ($ecount < $evidence_Length)
                    {
                        if(ISSET($vuln_evidence[$ecount][0])) {
                            $vdata = str_replace("                 ", " ",$vuln_evidence[$ecount][0]);
                            $vdata = str_replace(" 						"," ",$vdata);
                            $vdata = preg_replace("/<img[^>]+\>/i", "", $vdata);
                            $evidence .= "<td>$vdata</td>";}
                        if(ISSET($vuln_evidence[$ecount][1])) {
                            $vdata = str_replace("                 ", " ",$vuln_evidence[$ecount][1]);
                            $vdata = str_replace("                                          "," ",$vdata);
                            $vdata = preg_replace("/<img[^>]+\>/i", "", $vdata);
                            $evidence .= "<td>$vdata</td>";}
                        if(ISSET($vuln_evidence[$ecount][2])) {
                            $vdata = str_replace("                 ", " ",$vuln_evidence[$ecount][2]);
                            $vdata = str_replace("                                          "," ",$vdata);
                            $evidence .= "<td>$vdata</td>";}
                        if(ISSET($vuln_evidence[$ecount][3])) {
                            $vdata = str_replace("                 ", " ",$vuln_evidence[$ecount][3]);
                            $vdata = str_replace("                                          "," ",$vdata);
                            $evidence .= "<td>$vdata</td>";}
                        if(ISSET($vuln_evidence[$ecount][4])) {
                            $vdata = str_replace("                 ", " ",$vuln_evidence[$ecount][4]);
                            $vdata = str_replace("                                          "," ",$vdata);
                            $evidence .= "<td>$vdata</td>";}
                        if(ISSET($vuln_evidence[$ecount][5])) {
                            $vdata = str_replace("                 ", " ",$vuln_evidence[$ecount][5]);
                            $vdata = str_replace("                                          "," ",$vdata);
                            $evidence .= "<td>$vdata</td>";}
                        if(ISSET($vuln_evidence[$ecount][6])) {
                            $vdata = str_replace("                 ", " ",$vuln_evidence[$ecount][6]);
                            $vdata = str_replace("                                          "," ",$vdata);
                            $evidence .= "<td>$vdata</td>";}
                        if(ISSET($vuln_evidence[$ecount][7])) {
                            $vdata = str_replace("                 ", " ",$vuln_evidence[$ecount][7]);
                            $vdata = str_replace("                                          "," ",$vdata);
                            $evidence .= "<td>$vdata</td>";}
                        if(ISSET($vuln_evidence[$ecount][8])) {
                            $vdata = str_replace("                 ", " ",$vuln_evidence[$ecount][8]);
                            $vdata = str_replace("                                          "," ",$vdata);
                            $evidence .= "<td>$vdata</td>";}
                        $evidence .= "</tr>";
                        $ecount++;

                    }
                } else {
                    if(EMPTY($evidence)) {
                        $evidence = "No evidence was collected for this vulnerability";
                    }
                }

                $recommendation = $json_report_data->scan_output->scan_tests[$i]->recommendation;

                if($risklevel == "0") {
                    echo "<br />";
                    echo "<h5>$name</h5>";
                    echo "<hr>";
                } else {
                    echo "<br />";
                    echo "<h5>$name</h5>";
                    echo "<p>Risk level: $severity<br /></p>";
                    echo "<table class=\"table table-striped table-bordered\" width=\"100%\">$evidence</table><br />";

                    echo "<p>Risk description:<br /> $description</p>";
                    echo "<p>Recommendation:<br /> $recommendation</p>";
                    echo "<br />";
                    echo "<hr>";
                }
                $i++;
            }

            echo "<p>&nbsp;</p>";
            echo "<h5>Scan Statistics</h5>";
            echo "<table class=\"table table-striped table-bordered\" width=\"100%\">";
            echo "<tr><td>Scan Start Time</td><td>$start</td></tr>";
            echo "<tr><td>Scan Finish Time</td><td>$stop</td></tr>";
            echo "<tr><td>Scan Duration</td><td>$duration seconds</td></tr>";
            echo "<tr><td>Tests Performed</td><td>$num_tests</td></tr>";
            echo "<tr><td>Tests Completed</td><td>$num_finished_tests</td></tr>";
            echo "</table><br />";

        } else {
            echo "<div class=\"alert alert-danger\" role=\"alert\">
  <strong>An error has occured.</strong><br /><br />There is something wrong with the site $target and are unable to scan it at this time. Please try again later.
</div><p>&nbsp;</p>
<form class='form-inline' action='#' method='POST'>
<div class='input-group col-md-8'>
    <div class='input-group-prepend'>
        <div class='input-group-text'>URL: </div>
    </div>
    <input type='text' class='form-control' name='url' id='url' placeholder='URL to scan' value='https://'>
</div>
<div class='col-md-2'>
    <input class='btn btn-danger' type='submit' name='submit' id='submit' value='Scan URL'>
</div></form>";
        }


    } else {
        echo "<form class='form-inline' action='#' method='POST'>
<div class='input-group col-md-8'>
    <div class='input-group-prepend'>
        <div class='input-group-text'>URL: </div>
    </div>
    <input type='text' class='form-control' name='url' id='url' placeholder='URL to scan' value='https://'>
</div>
<div class='col-md-2'>
    <input class='btn btn-danger' type='submit' name='submit' id='submit' value='Scan URL'>
</div></form>";
    }
}

add_shortcode('freescan', 'freescan');

