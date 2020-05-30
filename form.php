<form class='form-inline' action='#' method='POST'>
    <div class='input-group col-md-8'>
        <div class='input-group-prepend'>
            <div class='input-group-text'>URL: </div>
        </div>
        <input type='text' class='form-control' name='url' id='url' placeholder='URL to scan' value='https://'>
    </div>
    <div class='col-md-2'>&nbsp;</div>
    <div class='input-group col-md-8'>
        <div class="form-check">
            <input class="form-check-input" type="checkbox" value="1" id="auth" name="auth">
            <label class="form-check-label" for="auth">I confirm I am authorised to scan this URL.</label>
        </div>
    </div>
    <div class='col-md-2'>
        <input type='hidden' name='userip' id='userip' value="<?php echo $_SERVER['REMOTE_ADDR'];?>">
        <input class='btn btn-danger' type='submit' name='submit' id='submit' value='Scan URL'>
    </div>
</form>
