<?php

define("ALGO", "SHA256");
define("SECRET_KEY", "7tu5zNCZhYv2q29V5JDZeskBPYbkERaHHsmkJjKSgpTWxxMAcHLzuBmmKyFXbGD7");
define("COOKIE_NAME", "ACCESS_TOKEN");
define("TOKEN_LIFETIME", 60);

$GLOBALS["__USER__"] = NULL;

function makeUserTokenPayload($user, $expired) {
  return [
    "uid" => $user['id'],
    "expired" => $expired,
    "validator" => $user['validator']
  ];
}

function payloadArrayToBase64($arr) {
  return base64_encode(json_encode($arr));
}

function payloadBase64ToArray($base64) {
  return json_decode(base64_decode($base64), TRUE);
}

// $overwriteValidator = TRUE => allow one device per user
function getUser($id, $overwriteValidator = FALSE) {
  $filePath = realpath(__DIR__) . DIRECTORY_SEPARATOR . "users.json";
  $json = file_get_contents($filePath);
  $users = json_decode($json, true);
  if (ISSET($users[$id])) {
    if ($overwriteValidator) {
      $users[$id]['validator'] = (string) time();
      file_put_contents($filePath, json_encode($users));
    }
    return $users[$id];
  }
  return FALSE;
}

function generateAccessToken($algo = ALGO, $payload_strings = '', $secretKey = SECRET_KEY) {
  return hash_hmac($algo, $payload_strings, $secretKey);
}

function verifyAccessToken($left, $right) {
  return hash_equals($left, $right);
}

function checkAccessToken($token_string, $token_origin, $refreshToken = FALSE) {
  $result = NULL;
  $token_payload = explode(".", $token_string);
  try {
    if ($token_payload && COUNT($token_payload) >= 2) {
      $payload = payloadBase64ToArray($token_payload[1]);
      $user = getUser($payload["uid"], FALSE);
      $payload["validator"] = $user["validator"];
      if ($user) {
        $access_token = generateAccessToken(ALGO, payloadArrayToBase64($payload), SECRET_KEY);
        if (verifyAccessToken($token_payload[0], $access_token) && ($payload["expired"] > time())) {
          if ($refreshToken) {
            $payload = makeUserTokenPayload($user, time() + TOKEN_LIFETIME);
            $access_token = generateAccessToken(ALGO, payloadArrayToBase64($payload), SECRET_KEY);
            array_pop($payload); // remove validator
            $at = implode(".", [$access_token, payloadArrayToBase64($payload)]);
            if ($token_origin === "COOKIE") {
              setcookie(COOKIE_NAME, $at, 0, "/", $_SERVER["SERVER_NAME"], FALSE, TRUE);
            } else if ($token_origin === "HEADER") {
              header("Authorization: $at");
            }
          }
          $user["access_token_origin"] = $token_origin;
          // $user["time"] = time();
          $user["expired"] = $payload["expired"];
          $result = $user;
        }
      }
    }
  } catch(\Exception $err) {
    die;
  }
  return $result;
}

function initilize() {
  if (isset(apache_request_headers()['Authorization'])) {
    $GLOBALS["__USER__"] = checkAccessToken(apache_request_headers()['Authorization'], "HEADER", TRUE); // to sanitize
  } else if (isset($_COOKIE[COOKIE_NAME])) {
    $GLOBALS["__USER__"] = checkAccessToken($_COOKIE[COOKIE_NAME], "COOKIE", TRUE); // to sanitize
  }
}
