# Freescan - A wordpress plugin

 * Plugin Name: Secure GI Free Scan
 * Plugin URI:  https://www.hedgehogsecurity.gi/secure-gi
 * Description: Secure GI - free website vulnerability scanner
 * Version:     1.0.0
 * Author:      Peter Bassill
 * Author URI:  https://peterbassill.com
 * License:     GNU
 * License URI: https://peterbassill.com/secure-gi

## Install Instructions
Download the repo and either zip it and install into wordpress via the UI or copy to your wp-contents/plugins folder.

Sign up to Pentest-Tools and get an API key. Put that API key in the config file. You should now be good to go.

## Todo
Add loader to front end to stop page timing out.

## Files
 * freescan.php - This is the core code
 * config.php - You will need to create this
 * functions.php - Wordpress plugin functions file
 * form.php - This is the form for the website
 * blacklist.php - This is the array of blacklisted websites. Sites not to scan.
