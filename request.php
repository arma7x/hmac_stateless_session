<?php
require_once(realpath(__DIR__) . DIRECTORY_SEPARATOR . "hmac.php");

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["OPERATION"])) {
  switch ($_POST["OPERATION"]) {
    case "LOGIN":
      if ($GLOBALS["__USER__"] === NULL && isset($_POST["uid"]) && $_POST["uid"] !== "") {
        $user = getUser($_POST["uid"], TRUE);
        if ($user) {
          $payload = makeUserTokenPayload($user, time() + TOKEN_LIFETIME);
          $access_token = generateAccessToken(ALGO, payloadArrayToBase64($payload), SECRET_KEY);
          array_pop($payload); // remove validator
          setcookie(COOKIE_NAME, implode(".", [$access_token, payloadArrayToBase64($payload)]), 0, "/", $_SERVER["SERVER_NAME"], FALSE, TRUE);
        }
      }
      break;
    case "LOGOUT":
      if ($GLOBALS["__USER__"] !== NULL) {
        $GLOBALS["__USER__"] = NULL;
        unset($_COOKIE[COOKIE_NAME]);
        setcookie(COOKIE_NAME, "", -1, "/");
      }
      break;
    case "REQUEST_ACCESS_TOKEN":
      if (isset($_POST["uid"]) && $_POST["uid"] !== "") {
        $uid = $_POST["uid"];
        $user = getUser($uid, TRUE);
        if ($user) {
          $payload = makeUserTokenPayload($user, time() + TOKEN_LIFETIME);
          $access_token = generateAccessToken(ALGO, payloadArrayToBase64($payload), SECRET_KEY);
          array_pop($payload); // remove validator
          echo json_encode(["access_token" => implode(".", [$access_token, payloadArrayToBase64($payload)])]);
        } else {
          http_response_code(400);
          echo json_encode(["error" => "$uid not exist!"]);
        }
      } else {
        http_response_code(400);
        echo json_encode(["error" => "UID is required!"]);
      }
      die;
      break;
    case "API":
      if ($GLOBALS["__USER__"] !== NULL) {
        header("Content-Type: application/json; charset=utf-8");
        echo json_encode($GLOBALS["__USER__"]);
      } else if ($GLOBALS["__USER__"] === NULL) {
        header("Content-Type: application/json; charset=utf-8");
        http_response_code(401);
        echo json_encode(["status" => "401 Unauthorized"]);
      }
      die;
      break;
  }

  header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
  header("Cache-Control: post-check=0, pre-check=0", false);
  header("Pragma: no-cache");
  header("Location: /");
  die();
}
