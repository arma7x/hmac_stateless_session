<?php
  require_once(realpath(__DIR__ . DIRECTORY_SEPARATOR . "hmac.php"));
  initilize();
  require_once(realpath(__DIR__ . DIRECTORY_SEPARATOR . "request.php"));
?>

<!DOCTYPE html>
<html>
  <meta charset="UTF-8">
  <title>HMAC Stateless Sesssion</title>
  <script>
    function makeApiRequest() {
      let access_token = document.getElementById('access_token').value;
      let formData = new FormData();
      formData.append('OPERATION', 'API');
      fetch("/", {
        headers: {
          'Accept': 'application/json',
          'Authorization': access_token,
        },
        method: "POST",
        body: formData
      })
      .then((res) => {
        if (res.headers.get('Authorization')) {
          document.getElementById('access_token').value = res.headers.get('Authorization');
          document.getElementById('access_token_info').value = JSON.stringify(JSON.parse(atob(res.headers.get('Authorization').split('.')[1], null, 2)), null, 2);
        }
        return res.json();
      })
      .then((json) => {
        document.getElementById('result').value = JSON.stringify(json, null, 2);
      })
      .catch((error) => {
        document.getElementById('result').value = JSON.stringify(error, null, 2);
      });
    }

    function makeTokenRequest(evt) {
      let uid = document.getElementById('uid').value;
      if (!uid) {
        alert("UID is required!");return;
      }
      let formData = new FormData();
      formData.append('OPERATION', 'REQUEST_ACCESS_TOKEN');
      formData.append('uid', uid);
      fetch("/", {
        headers: {
          'Accept': 'application/json',
        },
        method: "POST",
        body: formData
      })
      .then((res) => {
        if (res.status >= 400) {
          return res.json()
          .then(json => {
            return Promise.reject(json);
          })
          .catch(err => {
            return Promise.reject(err);
          });
        }
        return res.json();
      })
      .then((json) => {
        document.getElementById('access_token').value = json.access_token;
        document.getElementById('access_token_info').value = JSON.stringify(JSON.parse(atob(json.access_token.split('.')[1], null, 2)), null, 2);
        document.getElementById('result').value = '';
      })
      .catch((error) => {
        alert(error.error);
      });
    }
  </script>
  <body>
    <?php if ($GLOBALS["__USER__"] === NULL): ?>
      <form action="/index.php" method="POST">
        <input type="hidden" name="OPERATION" value="LOGIN">
        UID: <input id="uid" type="text" name="uid" required>
        <input type="submit" value="LOGIN">
        <button onclick="makeTokenRequest();return false;">REQUEST ACCESS TOKEN</button><br>
      </form>
      <br>
      <div style="display:flex;flex-direction:row;">
        <div style="display:flex;flex-direction:column;margin-right:10px;min-width:300px;">
          <textarea rows="9" id="access_token"></textarea>
          <textarea rows="5" id="access_token_info" style="margin-top:20px;"></textarea>
        </div>
        <textarea rows="15" id="result" style="min-width:300px;" disabled></textarea>
      </div>
      <br>
      <button onclick="makeApiRequest();">MAKE REQUEST USING ACCESS TOKEN</button>
    <?php else: ?>
      <form action="/index.php" method="POST">
        <pre><?php echo json_encode($GLOBALS["__USER__"], JSON_PRETTY_PRINT); ?></pre>
        <input type="hidden" name="OPERATION" value="LOGOUT">
        <input type="submit" value="LOGOUT">
      </form>
      <br>
    <?php endif ?>
  </body>
</html>
