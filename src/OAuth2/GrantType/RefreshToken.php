<?php
namespace OAuth2\GrantType;

/**
 * Refresh Token  Parameters 
 */
class RefreshToken implements IGrantType
{
    /**
     * Defines the Grant Type
     * 
     * @var string  Defaults to 'refresh_token'. 
     */
    const GRANT_TYPE = 'refresh_token';

    /**
     * Adds a specific Handling of the parameters
     * 
     * @return array of Specific parameters to be sent.
     * @param  mixed  $parameters the parameters array (passed by reference)
     */
    public function validateParameters(&$parameters)
    {
        if (!isset($parameters['refresh_token']))
        {
            throw new \Exception('The \'refresh_token\' parameter must be defined for the refresh token grant type');
        }
    }
}
