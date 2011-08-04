<?php
namespace OAuth2\GrantType;

/**
 * Password Parameters 
 */
class Password implements IGrantType
{
    /**
     * Defines the Grant Type
     * 
     * @var string  Defaults to 'password'. 
     */
    const GRANT_TYPE = 'password';
    
    /**
     * Adds a specific Handling of the parameters
     * 
     * @return array of Specific parameters to be sent.
     * @param  mixed  $parameters the parameters array (passed by reference)
     */
    public function validateParameters(&$parameters)
    {
        if (!isset($parameters['username']))
        {
            throw new \Exception('The \'username\' parameter must be defined for the Password grant type');
        }
        elseif (!isset($parameters['password']))
        {
            throw new \Exception('The \'password\' parameter must be defined for the Password grant type');
        }
    }
}
