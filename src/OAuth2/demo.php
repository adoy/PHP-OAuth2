<?php
require('client.php');
require('GrantType/IGrantType.php');
require('GrantType/AuthorizationCode.php');

const CLIENT_ID     = 'your client id';
const CLIENT_SECRET = 'your client secret';

const REDIRECT_URI           = 'http://url/of/this.php';
const AUTHORIZATION_ENDPOINT = 'https://alchemy1.nationbuilder.com//oauth/authorize';
const TOKEN_ENDPOINT         = 'https://alchemy1.nationbuilder.com/oauth/access_token';

$client = new OAuth2\Client(CLIENT_ID, CLIENT_SECRET);
if (!isset($_GET['code']))
{
    $auth_url = $client->getAuthenticationUrl(AUTHORIZATION_ENDPOINT, REDIRECT_URI);
    header('Location: ' . $auth_url);
    die('Redirect');
}
else
{
    $params = array('code' => $_GET['code'], 'redirect_uri' => REDIRECT_URI);
    $response = $client->getAccessToken(TOKEN_ENDPOINT, 'authorization_code', $params);
    parse_str($response['result'], $info);
    $client->setAccessToken($info['access_token']);
    $response = $client->fetch('https://alchemy1.nationbuilder.com/me');
    var_dump($response, $response['result']);
}
namespace OAuth2\GrantType;

/**
 * MyCustomGrantType Grant Type 
 */
class MyCustomGrantType implements IGrantType
{
    /**
     * Defines the Grant Type
     * 
     * @var string  Defaults to 'my_custom_grant_type'. 
     */
    const GRANT_TYPE = 'my_custom_grant_type';

    /**
     * Adds a specific Handling of the parameters
     * 
     * @return array of Specific parameters to be sent.
     * @param  mixed  $parameters the parameters array (passed by reference)
     */
    public function validateParameters(&$parameters)
    {
        if (!isset($parameters['first_mandatory_parameter']))
        {
            throw new \Exception('The \'first_mandatory_parameter\' parameter must be defined for the Password grant type');
        }
        elseif (!isset($parameters['second_mandatory_parameter']))
        {
            throw new \Exception('The \'seconde_mandatory_parameter\' parameter must be defined for the Password grant type');
        }
    }
}

call the OAuth client getAccessToken with the grantType you defined in the GRANT_TYPE constant, As following : 
$response = $client->getAccessToken(TOKEN_ENDPOINT, 'my_custom_grant_type', $params);
?>
