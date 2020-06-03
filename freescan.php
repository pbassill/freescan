<?php

/*
 * Plugin Name: Secure GI Free Scan
 * Plugin URI:  https://www.hedgehogsecurity.gi/secure-gi
 * Description: Secure GI - free website vulnerability scanner
 * Version:     1.0.2
 * Author:      Peter Bassill
 * Author URI:  https://peterbassill.com
 * License:     CC BY 4.0
 * License URI: https://creativecommons.org/licenses/by/4.0/
 *
 * */

include('securewp.php');
include('config.php');
include('functions.php');
include('blacklist.php');

function freescan()
{
    if (ISSET($_POST['submit'])) {
        $target = $_POST['url'];
        $cip = $_SERVER['REMOTE_ADDR'];
        $userip = $_POST['userip'];
        $auth = $_POST['auth'];

        // Check for authorisation
        if($auth != 1){
            logger("CIP:$cip TARGET:$target STATUS:ERROR - Auth not checked.");
            error_msg('Not Authorised', 'Please confirm you have authorisation to scan this URL.');
            include('form.php');
        }

        // Check target against blacklist
        elseif(check_blacklist($target)) {
            logger("CIP:$cip TARGET:$target STATUS:ERROR - Target is in blacklist.");
            error_msg('Prohibited Target.', 'You attempted to scan a prohibited URL. That is forbidden.');
            include('form.php');
        }

        // Check to see if the post'd IP is different
        elseif($userip == $cip) {
            logger("CIP:$cip TARGET:$target STATUS:queued");

            // Lets do some sanitization on the target
            // Check for trailing / and remove it
            $target = rtrim($target, "/");

            // Replace the below section with sending the job to a worker and monitor DB for output.
            exec("php scan.php $target $cip > /dev/null &");

            // Get the scan status and update the UI
            if ($scan_status = "running") {
                // update the ui and refresh
            }

            if ($scan_status == "finished") {
                // Get the scan output
                $stmt = $pdo->query("SELECT * FROM scans WHERE cip=$cip AND target=$target");
                for($stmt as $row) {
                    $high_count = $row['high_count'];
                    $medium_count = $row['medium_count'];
                    $low_count = $row['low_count'];
                    $info_count = $row['info_count'];
                    $start = $row['start'];
                    $stop = $row['stop'];
                    $duration = $row['duration'];
                    $num_test = $row['num_tests'];
                    $nun_finished_tests = $row['num_finished_tests'];
                }

                echo "<h5>Overall Risk Level: ";
                if ($high_count >= '1') { echo "<button type=\"button\" class=\"btn btn-danger\">High</button>";}
                elseif ($medium_count >= '1') {echo "<button type=\"button\" class=\"btn btn-warning\">Medium</button>";}
                elseif ($low_count >= '1') {echo "<button type=\"button\" class=\"btn btn-success\">Low</button>";}
                else {echo "<button type=\"button\" class=\"btn btn-info\">Zero</button>";

                echo "<p>&nbsp;</p>";
                echo "<h5>Vulnerability Summary</h5>";
                echo "<table class=\"table table-striped table-bordered\">";
                echo "<thead><tr><th>Criticality</th><th>Count</th></tr></thead>";
                echo "<body><tr><td>High</td><td>$high_count</td></tr>";
                echo "<tr><td>Medium</td><td>$medium_count</td></tr>";
                echo "<tr><td>Low</td><td>$low_count</td></tr>";
                echo "<tr><td>Informational</td><td>$info_count</td></tr></tbody></table>";
                echo "<p>&nbsp;</p>";


                echo "<h4>Findings</h4>";

                $stmt = $pdo->query("SELECT * FROM vulnerabilities WHERE cip=$cip AND target=$target");
                for($stmt as $row) {
                    $name = $row['name'];
                    $description = $row['description'];
                    $evidence = $row['vuln_evidence'];
                    $risklevel = $row['risklevel'];
                    $evidence = $row['evidence'];
                    $description = $row['description'];
                    $recommendation = $row['recommendaton'];
                }

                $severity = "<button type=\"button\" class=\"btn btn-info btn-sm\">Informational</button>";
                if ($risklevel == "0") { $severity = "<button type=\"button\" class=\"btn btn-info btn-sm\">Informational</button>";}
                if ($risklevel == "1") {$severity = "<button type=\"button\" class=\"btn btn-success btn-sm\">Low</button>";}
                if ($risklevel == "2") {$severity = "<button type=\"button\" class=\"btn btn-warning btn-sm\">Medium</button>";}
                if ($risklevel == "3") {$severity = "<button type=\"button\" class=\"btn btn-danger btn-sm\">High</button>";}

                if ($risklevel == "0") {
                    echo "<br />";
                    echo "<h5>$name</h5>";
                    echo "<hr>";
                } else {
                    echo "<br />";
                    echo "<h5>$name</h5>";
                    echo "<p>Risk level: $severity<br /></p>";
                    echo "<table class=\"table table-striped table-bordered\">$evidence</table><br />";
                    echo "<p>Risk description:<br /> $description</p>";
                    echo "<p>Recommendation:<br /> $recommendation</p>";
                    echo "<br />";
                    echo "<hr>";
                }

                echo "<p>&nbsp;</p>";
                echo "<h5>Scan Statistics</h5>";
                echo "<table class=\"table table-striped table-bordered\">";
                echo "<tr><td>Scan Start Time</td><td>$start</td></tr>";
                echo "<tr><td>Scan Finish Time</td><td>$stop</td></tr>";
                echo "<tr><td>Scan Duration</td><td>$duration seconds</td></tr>";
                echo "<tr><td>Tests Performed</td><td>$num_tests</td></tr>";
                echo "<tr><td>Tests Completed</td><td>$num_finished_tests</td></tr>";
                echo "</table><br />";

            } else {
                echo "<div class=\"alert alert-danger\" role=\"alert\">
                    <strong>An error has occured.</strong><br /><br />There is something wrong with the site $target and are unable to scan it at this time. It could be that you need to add the prefix 'www' or remove the 'www' from the URL. Please try again. If it continues to fail, please try back later as we check the logs often.
                    </div><p>&nbsp;</p>";
                include('form.php');
            }
        } else {
            logger("CIP:$cip TARGET:$target STATUS:ERROR - Security bypass detected.");
            echo "<div class=\"alert alert-danger\" role=\"alert\">
                    <strong>Security bypass detected.</strong><br /><br />It would appear that you are trying to bypass the usage tracking. That is forbidden.
                    </div>";
            include('form.php');
        }
    } else {
        include('form.php');
    }
}

add_shortcode('freescan', 'freescan');
