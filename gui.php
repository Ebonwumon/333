<?php
?>

<html>
<head>
    <title>WOW SO CRACK ME</title>
    <link rel="stylesheet" href="http://yui.yahooapis.com/pure/0.3.0/pure-min.css">
    <script src="http://code.jquery.com/jquery-2.0.3.min.js"></script>
    <style>
        .pure-button {
            margin-right: 0.1em;
            margin-bottom:0.1em;
        }
    </style>
</head>
<body>
    <h3>Let's get cracking</h3>
    <hr/>
    <form action="api.php" method="GET" id="crackMe">
        <label for="maxChars">Characters to work with: </label>
        <input type="number" value="500" name="maxChars" />

        <br />

        <label for="text">
            Character:
        </label>
        <input type="text" name="char" />

        <label for="position">Assert for position: </label>
        <input type="number" name="position" />

        <input type="submit" value="Get it done" class="pure-button pure-button-primary">
    </form>

    <hr />
    <div id="key">

    </div>
    <h4>Decrypted Text: <span id="decryptedLength">(xxx)</span> Chars</h4>
    <div id="crackable">

    </div>

<script>
    $(document).ready(function() {
        fillCrackedText();
        fillKey();

        $('#crackMe').submit(function(e) {
            e.preventDefault();
            $.ajax({
                type: "GET",
                url: "api.php",
                dataType: "json",
                data: {
                    maxChars: $('input[name=maxChars]').val(),
                    text: $('input[name=char]').val(),
                    position: $('input[name=position]').val()
                    },
                success: function(data) {
                    console.log(data);
                    insertKey(data["key"], data["position"]);
                    insertDecryption(data.decryption);
                },
                error: function(jqxhr) {
                    console.log("error");
                    console.log(jqxhr);
                }
            });
        });
    });

    function insertKey(key, position) {
        $('#key').children().each(function() {
           if ($(this).data("position") == position) {
               $(this).html(key);
               return false;
           }
        });
    }

    function insertDecryption(decrypted) {
        for (var i in decrypted) {
            $('#crackable').find('[data-position=' + i + ']').html(decrypted[i]);
        }
    }

    function fillKey() {
        // MAGIC NUMBER KEY LENGTH
        for (var i = 0; i < 33; i++) {
            $('#key').append("<span data-position=\'" + i + "\'></span>");
        }
    }

    function fillCrackedText() {
        for (var i = 0; i < $('input[name=maxChars]').val(); i++) {
            $('#crackable').append("<button class=\'pure-button\' data-position=\'" + i + "\'>u</button>");
        }
    }
</script>
</body>
</html>