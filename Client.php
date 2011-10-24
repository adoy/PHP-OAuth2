<?php
/**
 * Note : Code is released under the GNU LGPL
 *
 * Please do not change the header of this file
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Lesser General Public License for more details.
 */

/**
 * Light PHP wrapper for the OAuth 2.0 protocol.
 *
 * This client is based on the OAuth2 specification draft v2.15
 * http://tools.ietf.org/html/draft-ietf-oauth-v2-15
 *
 * @author      Pierrick Charron <pierrick@webstart.fr>, Anis BEREJEB <anis.berejeb@gmail.com> 
 * @version     1.0
 */
namespace OAuth2;

class Client
{
    /**
     * Different AUTH method
     */
    const AUTH_TYPE_URI                 = 0;
    const AUTH_TYPE_AUTHORIZATION_BASIC = 1;
    const AUTH_TYPE_FORM                = 2;
    
    /**
     * Different Access token type
     */
    const ACCESS_TOKEN_URI      = 0;   
    const ACCESS_TOKEN_BEARER   = 1;
    const ACCESS_TOKEN_OAUTH    = 2;
    const ACCESS_TOKEN_MAC      = 3;

    /**
    * Different Grant types
    */
    const GRANT_TYPE_AUTH_CODE          = 'authorization_code';
    const GRANT_TYPE_PASSWORD           = 'password';
    const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';
    const GRANT_TYPE_REFRESH_TOKEN      = 'refresh_token';

    /**
     * HTTP Methods
     */
    const HTTP_METHOD_GET    = 'GET';
    const HTTP_METHOD_POST   = 'POST';
    const HTTP_METHOD_PUT    = 'PUT';
    const HTTP_METHOD_DELETE = 'DELETE';
    const HTTP_METHOD_HEAD   = 'HEAD';
    
    /**
     * HTTP Form content types
     */
    const HTTP_FORM_CONTENT_TYPE_APPLICATION = 0;
    const HTTP_FORM_CONTENT_TYPE_MULTIPART = 1;

    /**
     * Client ID
     * 
     * @var string
     */
    protected $client_id = null;

    /**
     * Client Secret
     * 
     * @var string
     */
    protected $client_secret = null;

    /**
     * Client Authentication method
     * 
     * @var int
     */
    protected $client_auth = self::AUTH_TYPE_URI;

    /**
     * Access Token
     *
     * @var string
     */
    protected $access_token = null;

    /**
     * Access Token Type
     *
     * @var int
     */
    protected $access_token_type = self::ACCESS_TOKEN_URI;

    /**
     * Access Token Secret
     *
     * @var string
     */
    protected $access_token_secret = null;

    /**
     * Access Token crypt algorithm
     *
     * @var string
     */
    protected $access_token_algorithm = null;
    
    /**
     * Access Token Parameter name
     *
     * @var string
     */
    protected $access_token_param_name = 'access_token';

    /**
     * Construct 
     * 
     * @param string $client_id Client ID
     * @param string $client_secret Client Secret
     * @param int    $client_auth (AUTH_TYPE_URI, AUTH_TYPE_AUTHORIZATION_BASIC, AUTH_TYPE_FORM)
     */
    public function __construct($client_id, $client_secret, $client_auth = self::AUTH_TYPE_URI)
    {
        if (!extension_loaded('curl')) {
            throw new \Exception('The PHP exention curl must be installed to use this library.');
        }
        
        $this->client_id     = $client_id;
        $this->client_secret = $client_secret;
        $this->client_auth   = $client_auth;
    }

    /**
     * Get the client Id
     *
     * @return string Client ID
     */
    public function getClientId()
    {
        return $this->client_id;
    }

    /**
     * Get the client Secret
     * 
     * @return string Client Secret
     */
    public function getClientSecret()
    {
        return $this->client_secret;
    }
    
    /**
     * getAuthenticationUrl
     *
     * @param string $auth_endpoint Url of the authentication endpoint
     * @param string $redirect_uri  Redirection URI
     * @param array  $extra_parameters  Array of extra parameters like scope or state (Ex: array('scope' => null, 'state' => ''))
     * @return string URL used for authentication
     */
    public function getAuthenticationUrl($auth_endpoint, $redirect_uri, array $extra_parameters = array())
    {
        $parameters = array_merge($extra_parameters, array(
            'response_type' => 'code',
            'client_id'     => $this->client_id,
            'redirect_uri'  => $redirect_uri
        ));
        return $auth_endpoint . '?' . http_build_query($parameters, null, '&');
    }
    
    /**
     * getAccessToken
     *
     * @param string $token_endpoint    Url of the token endpoint
     * @param int    $grant_type        Grand Type ('authorization_code', 'password', 'client_credentials', 'refresh_token', or a custom code (@see GrantType Classes)
     * @param array  $parameters        Array sent to the server (depend on which grant type you're using)
     * @return array Array of parameters required by the grant_type (CF SPEC)
     */
    public function getAccessToken($token_endpoint, $grant_type, array $parameters)
    {
        if (!$grant_type)
        {
            throw new \InvalidArgumentException('grant_type is mandatory.');
        }
        $grantTypeClassName = $this->convertToCamelCase($grant_type);
        $grantTypeClass =  __NAMESPACE__ . '\\GrantType\\' . $grantTypeClassName;
        if (!class_exists($grantTypeClass)) {
            throw new \InvalidArgumentException('unknown grant type ' . $grant_type);
        }
        $grantTypeObject = new $grantTypeClass();
        $grantTypeObject->validateParameters($parameters);
        if (!defined($grantTypeClass . '::GRANT_TYPE')) {
            throw new \Exception('Unknown constant GRANT_TYPE for class ' . $grantTypeClassName);
        }
        $parameters['grant_type'] = $grantTypeClass::GRANT_TYPE;
        $http_headers = array();
        switch ($this->client_auth)
        {
            case self::AUTH_TYPE_URI:
            case self::AUTH_TYPE_FORM:
                $parameters['client_id'] = $this->client_id;
                $parameters['client_secret'] = $this->client_secret;
                break;
            case self::AUTH_TYPE_AUTHORIZATION_BASIC:
                $parameters['client_id'] = $this->client_id;
                $http_headers['Authorization'] = 'Basic ' . base64_encode($this->client_id .  ':' . $this->client_secret);
                break;
            default:
                throw new Exception('Unknown client auth type.');
                break;
        }

        return $this->executeRequest($token_endpoint, $parameters, self::HTTP_METHOD_POST, $http_headers, self::HTTP_FORM_CONTENT_TYPE_APPLICATION);
    }

    /**
     * setToken
     *
     * @param string $token Set the access token
     * @return void
     */
    public function setAccessToken($token)
    {
        $this->access_token = $token;
    }

    /**
     * Set the client authentication type
     * 
     * @param string $client_auth (AUTH_TYPE_URI, AUTH_TYPE_AUTHORIZATION_BASIC, AUTH_TYPE_FORM)
     * @return void
     */
    public function setClientAuthType($client_auth)
    {
        $this->client_auth = $client_auth;
    }


    /**
     * Set the access token type
     *
     * @param int $type Access token type (ACCESS_TOKEN_BEARER, ACCESS_TOKEN_MAC, ACCESS_TOKEN_URI)
     * @param string $secret The secret key used to encrypt the MAC header
     * @param string $algorithm Algorithm used to encrypt the signature
     * @return void
     */
    public function setAccessTokenType($type, $secret = null, $algorithm = null)
    {
        $this->access_token_type = $type;
        $this->access_token_secret = $secret;
        $this->access_token_algorithm = $algorithm;
    }

    /**
     * Fetch a protected ressource
     * 
     * @param string $protected_ressource_url Protected resource URL
     * @param array  $parameters Array of parameters
     * @param string $http_method HTTP Method to use (POST, PUT, GET, HEAD, DELETE)
     * @param array  $http_headers HTTP headers
     * @param int    $form_content_type HTTP form content type to use
     * @return array
     */
    public function fetch($protected_resource_url, array $parameters = array(), $http_method = self::HTTP_METHOD_GET, array $http_headers = array(), $form_content_type = self::HTTP_FORM_CONTENT_TYPE_MULTIPART)
    {
        if ($this->access_token)
        {
            switch ($this->access_token_type)
            {
                case self::ACCESS_TOKEN_URI:
                    $parameters[$this->access_token_param_name] = $this->access_token;
                    break;
                case self::ACCESS_TOKEN_BEARER:
                    $http_headers['Authorization'] = 'Bearer ' . $this->access_token;
                    break;
                case self::ACCESS_TOKEN_OAUTH:
                    $http_headers['Authorization'] = 'OAuth ' . $this->access_token;
                    break;
                case self::ACCESS_TOKEN_MAC:
                    $http_headers['Authorization'] = 'MAC ' . $this->generateMACSignature($protected_resource_url, $parameters, $http_method);
                    break;
                default:
                    throw new Exception('Unknown access token type.');
                    break;
            }
        }
        return $this->executeRequest($protected_resource_url, $parameters, $http_method, $http_headers, $form_content_type);
    }

    /**
     * Generate the MAC signature 
     *
     * @param string $url Called URL
     * @param array  $parameters Parameters
     * @param string $http_method Http Method
     * @return string
     */
    private function generateMACSignature($url, array $parameters, $http_method)
    {
        $timestamp = time();
        $nonce = uniqid();
        $query_parameters = array();
        $body_hash = '';
        $parsed_url = parse_url($url);
        if (!isset($parsed_url['port'])) 
        {
            $parsed_url['port'] = ($parsed_url['scheme'] == 'https') ? 443 : 80;
        }

        if (self::HTTP_METHOD_POST === $http_method || self::HTTP_METHOD_PUT === $http_method)
        {
            if ($parameters) 
            {
                $body_hash = base64_encode(hash($this->access_token_algorithm, $parameters));
            }
        }
        else
        {
            foreach ($parameters as $key => $parsed_urlvalue)
            {
                $query_parameters[] = rawurlencode($key) . '=' . rawurlencode($parsed_urlvalue);
            }
            sort($query_parameters);
        }

        $signature = base64_encode(hash_hmac($this->access_token_algorithm, 
                    $this->access_token . "\n"
                    . $timestamp . "\n" 
                    . $nonce . "\n" 
                    . $body_hash . "\n"
                    . $http_method . "\n" 
                    . $parsed_url['host'] . "\n"
                    . $parsed_url['port'] . "\n"
                    . $parsed_url['path'] . "\n"
                    . implode($query_parameters, "\n")
                    , $this->access_token_secret));

        return 'token="' . $this->access_token . '", timestamp="' . $timestamp . '", nonce="' . $nonce . '", signature="' . $signature . '"';
    }

    /**
     * Execute a request (with curl)
     *
     * @param string $url URL
     * @param mixed  $parameters Array of parameters
     * @param string $http_method HTTP Method
     * @param array  $http_headers HTTP Headers
     * @param int    $form_content_type HTTP form content type to use
     * @return array 
     */
    private function executeRequest($url, array $parameters = array(), $http_method = self::HTTP_METHOD_GET, array $http_headers = null, $form_content_type = self::HTTP_FORM_CONTENT_TYPE_MULTIPART)
    {
        $curl_options = array(
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_CUSTOMREQUEST  => $http_method
                );

        switch($http_method)
        {
            case self::HTTP_METHOD_POST:
                $curl_options[CURLOPT_POST] = true;
                /* No break */
            case self::HTTP_METHOD_PUT:
                
                /**
                 * Passing an array to CURLOPT_POSTFIELDS will encode the data as multipart/form-data, 
                 * while passing a URL-encoded string will encode the data as application/x-www-form-urlencoded.
                 * http://php.net/manual/en/function.curl-setopt.php
                 */
                if(self::HTTP_FORM_CONTENT_TYPE_APPLICATION === $form_content_type)
                {
                    $parameters = http_build_query($parameters);
                }
                $curl_options[CURLOPT_POSTFIELDS] = $parameters;
                break;
            case self::HTTP_METHOD_HEAD:
                $curl_options[CURLOPT_NOBODY] = true;
                /* No break */
            case self::HTTP_METHOD_DELETE:
            case self::HTTP_METHOD_GET:
                $url .= '?' . http_build_query($parameters, null, '&');
                break;
            default:
                break;
        }

        $curl_options[CURLOPT_URL] = $url;

        if (is_array($http_headers)) 
        {
            $header = array();
            foreach($http_headers as $key => $parsed_urlvalue) {
                $header[] = "$key: $parsed_urlvalue";
            }
            $curl_options[CURLOPT_HTTPHEADER] = $header;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $curl_options);
        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);

        $json_decode = json_decode($result, true);
        return array(
                'result' => (null === $json_decode) ? $result : $json_decode,
                'code' => $http_code,
                'content_type' => $content_type
                );
    }

    /**
     * Set the name of the parameter that carry the access token
     *
     * @param string $name Token parameter name
     * @return void
     */
    public function setAccessTokenParamName($name)
    {
        $this->access_token_param_name = $name;
    }

    /**
     * Converts the class name to camel case
     * 
     * @param  mixed  $grant_type  the grant type
     * @return string
     */
    private function convertToCamelCase($grant_type)
    {
        $parts = explode('_', $grant_type);
        array_walk($parts, function(&$item) { $item = ucfirst($item);});
        return implode('', $parts);
    }


}

class Exception extends \Exception
{
}
