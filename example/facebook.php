<?php
require('../src/OAuth2/Client.php');
require('../src/OAuth2/GrantType/IGrantType.php' );
require('../src/OAuth2/GrantType/AuthorizationCode.php' );
require('../src/OAuth2/GrantType/ClientCredentials.php' );

const CLIENT_ID     = '';
const CLIENT_SECRET = '';

const REDIRECT_URI           = 'http://localhost/git/Work/PHP-OAuth2/example/facebook.php';
const AUTHORIZATION_ENDPOINT = 'https://graph.facebook.com/oauth/authorize';
const TOKEN_ENDPOINT         = 'https://graph.facebook.com/oauth/access_token';

$client = new OAuth2\Client(CLIENT_ID, CLIENT_SECRET);
if (!isset($_GET['code']))
{
    $auth_url = $client->getAuthenticationUrl(AUTHORIZATION_ENDPOINT, REDIRECT_URI);
    header('refresh: 2; url=' . $auth_url);
    die('Redirect');
}
else
{
    $params = array('code' => $_GET['code'], 'redirect_uri' => REDIRECT_URI);
    $response = $client->getAccessToken(TOKEN_ENDPOINT, 'authorization_code', $params);
    // $response = $client->getAccessToken(TOKEN_ENDPOINT, 'client_credentials', $params);
    parse_str($response['result'], $info);
    $client->setAccessToken($info['access_token']);
    $response = $client->fetch('https://graph.facebook.com/me');
    var_dump($response, $response['result']);
}
