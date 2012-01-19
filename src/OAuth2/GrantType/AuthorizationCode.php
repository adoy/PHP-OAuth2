<?php
namespace OAuth2\GrantType;

/**
 * Authorization code  Grant Type Validator
 */
class AuthorizationCode implements IGrantType
{
    /**
     * Defines the Grant Type
     * 
     * @var string  Defaults to 'authorization_code'. 
     */
    const GRANT_TYPE = 'authorization_code';

    /**
     * Adds a specific Handling of the parameters
     * 
     * @return array of Specific parameters to be sent.
     * @param  mixed  $parameters the parameters array (passed by reference)
     */
    public function validateParameters(&$parameters)
    {
        if (!isset($parameters['code']))
        {
            throw new \Exception('The \'code\' parameter must be defined for the Authorization Code grant type');
        }
        elseif (!isset($parameters['redirect_uri']))
        {
            throw new \Exception('The \'redirect_uri\' parameter must be defined for the Authorization Code grant type');
        }
    }
}
