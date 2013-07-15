Simple OAuth2 client for PHP
============================

Author & Contact
----------------

Charron Pierrick
    - pierrick@webstart.fr

Berejeb Anis
    - anis.berejeb@gmail.com


Documentation & Download
------------------------

Latest version is available on github at :
    - https://github.com/adoy/PHP-OAuth2

Documentation can be found on :
    - https://github.com/adoy/PHP-OAuth2


License
-------

This Code is released under the GNU LGPL

Please do not change the header of the file(s).

This library is free software; you can redistribute it and/or modify it
under the terms of the GNU Lesser General Public License as published
by the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.

See the GNU Lesser General Public License for more details.


Usage instructions
------------------

```php
<?php

include 'vendor/autoload.php';

$clientId = 'your client id';
$clientSecret = 'your client secret';

$redirectUri = 'http://url/of/this.php';
$authorizationEndPoint = 'https://graph.facebook.com/oauth/authorize';
$tokenEndPoint = 'https://graph.facebook.com/oauth/access_token';

$client = new OAuth2\Client($clientId, $clientSecret);
if (!isset($_GET['code']))
{
    $auth_url = $client->getAuthenticationUrl($authorizationEndPoint, $redirectUri);
    header('Location: ' . $auth_url);
    die('Redirect');
}
else
{
    $params = array('code' => $_GET['code'], 'redirect_uri' => $redirectUri);
    $response = $client->getAccessToken($tokenEndPoint, 'authorization_code', $params);
    parse_str($response['result'], $info);
    $client->setAccessToken($info['access_token']);
    $response = $client->fetch('https://graph.facebook.com/me');
    var_dump($response, $response['result']);
}
```

Adding a new grand type
-----------------------

Simply write a new class in the namespace OAuth2\GrantType. You can place the class file under GrantType.
Here is an example :

```php
<?php

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
```

Call the OAuth client getAccessToken with the grantType you defined in the GRANT_TYPE constant, as follows:

```php
$response = $client->getAccessToken(TOKEN_ENDPOINT, 'my_custom_grant_type', $params);

```

