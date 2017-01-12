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

$response = $client->getAccessToken(TOKEN_ENDPOINT, 'my_custom_grant_type', $params);
?>
