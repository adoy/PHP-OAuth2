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
 * @author      Pierrick Charron <pierrick@webstart.fr> 
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
     * Different Grant types
     */
    const GRANT_TYPE_AUTH_CODE          = 0;
    const GRANT_TYPE_PASSWORD           = 1;
    const GRANT_TYPE_CLIENT_CREDENTIALS = 2;
    const GRANT_TYPE_REFRESH_TOKEN      = 3;
    const GRANT_TYPE_CUSTOM             = 4;

    /**
     * Different Access token type
     */
    const ACCESS_TOKEN_URI      = 0;   
    const ACCESS_TOKEN_BEARER   = 1;
    const ACCESS_TOKEN_OAUTH    = 2;
    const ACCESS_TOKEN_MAC      = 3;
    
    /**
     * HTTP Methods
     */
    const HTTP_METHOD_GET    = 'GET';
    const HTTP_METHOD_POST   = 'POST';
    const HTTP_METHOD_PUT    = 'PUT';
    const HTTP_METHOD_DELETE = 'DELETE';
    const HTTP_METHOD_HEAD   = 'HEAD';

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
     * Construct 
     * 
     * @param string $client_id Client ID
     * @param string $client_secret Client Secret
     * @param int    $client_auth (AUTH_TYPE_URI, AUTH_TYPE_AUTHORIZATION, AUTH_TYPE_FORM)
     */
    public function __construct($client_id, $client_secret, $client_auth = self::AUTH_TYPE_URI)
    {
        if (!extension_loaded('curl')) {
            throw new Exception('The PHP exention curl must be installed to use this library.');
        }
        
        $this->client_id     = $client_id;
        $this->client_secret = $client_secret;
        $this->client_auth   = $client_auth;
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
     * @param int    $grant_type        Grand Type (GRANT_TYPE_AUTH_CODE, GRANT_TYPE_PASSWORD, GRANT_TYPE_CLIENT_CREDENTIALS, GRANT_TYPE_REFRESH_TOKEN, GRANT_TYPE_CUSTOM)
     * @param array  $parameters        Array sent to the server (depend on which grant type you're using)
     * @param string $custom_grant_url  URL of the custom grant type
     * @return array Array of parameters required by the grant_type (CF SPEC)
     */
    public function getAccessToken($token_endpoint, $grant_type, array $parameters, $custom_grant_url = null)
    {
        switch ($grant_type)
        {
            case self::GRANT_TYPE_AUTH_CODE:
                if (!isset($parameters['code']))
                {
                    throw new Exception('The \'code\' parameter must be defined for the GRANT_TYPE_AUTH_CODE grant type');
                } 
                elseif (!isset($parameters['redirect_uri']))
                {
                    throw new Exception('The \'redirect_uri\' parameter must be defined for the GRANT_TYPE_AUTH_CODE grant type');
                }
                $parameters['grant_type'] = 'authorization_code';
                break;

            case self::GRANT_TYPE_PASSWORD:
                if (!isset($parameters['username']))
                {
                    throw new Exception('The \'username\' parameter must be defined for the GRANT_TYPE_PASSWORD grant type');
                } 
                elseif (!isset($parameters['password']))
                {
                    throw new Exception('The \'password\' parameter must be defined for the GRANT_TYPE_PASSWORD grant type');
                }
                $parameters['grant_type'] = 'password';
                break;

            case self::GRANT_TYPE_CLIENT_CREDENTIALS:
                $parameters['grant_type'] = 'client_credentials';
                break;

            case self::GRANT_TYPE_REFRESH_TOKEN:
                if (!isset($parameters['refresh_token']))
                {
                    throw new Exception('The \'refresh_token\' parameter must be defined for the GRANT_TYPE_REFRESH_TOKEN grant type');
                }
                $parameters['grant_type'] = 'refresh_token';

                break;

            case self::GRANT_TYPE_CUSTOM:
                throw new Exception('Grant type custom is not yet implemented');
                break;

            default:
                throw new Exception('Unknown grant type.');
                break;
        }

        $http_headers = array();
        switch ($this->client_auth)
        {
            case self::AUTH_TYPE_URI:
            case self::AUTH_TYPE_FORM:
                $parameters['client_id'] = $this->client_id;
                $parameters['client_secret'] = $this->client_secret;
                break;
            case self::AUTH_TYPE_AUTHORIZATION_BASIC:
                $http_headers['Authorization'] = 'Basic ' . base64_encode($this->client_id .  ':' . $this->client_secret);
                break;
            default:
                throw new Exception('Unknown client auth type.');
                break;
        }

        return $this->executeRequest($token_endpoint, $parameters, self::HTTP_METHOD_POST, $http_headers);
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
     * @param string $client_auth (AUTH_TYPE_URI, AUTH_TYPE_AUTHORIZATION, AUTH_TYPE_FORM)
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
     * @return array
     */
    public function fetch($protected_resource_url, array $parameters = array(), $http_method = self::HTTP_METHOD_GET, array $http_headers = array())
    {
        if ($this->access_token)
        {
            switch ($this->access_token_type)
            {
                case self::ACCESS_TOKEN_URI:
                    $parameters['access_token'] = $this->access_token;
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
        return $this->executeRequest($protected_resource_url, $parameters, $http_method, $http_headers);
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
            foreach ($parameters as $key => $parsed_urlalue)
            {
                $query_parameters[] = rawurlencode($key) . '=' . rawurlencode($parsed_urlalue);
            }
            sort($query_parameters);
        }

        $signature = base64_encode(hash_hmac($this->access_token_algorithm, 
                    $this->access_token . "\n"
                    . $timestamp . "\n" 
                    . $nonce . "\n" 
                    . $body_hash . "\n"
                    . $method . "\n" 
                    . $parsed_url['hostname'] . "\n"
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
     * @param mixed $parameters Array of parameters
     * @param string $http_method HTTP Method
     * @param array $http_headers HTTP Headers
     * @return array 
     */
    private function executeRequest($url, array $parameters = array(), $http_method = self::HTTP_METHOD_GET, array $http_headers = null)
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
            foreach($http_headers as $key => $parsed_urlalue) {
                $header[] = "$key: $parsed_urlalue";
            }
            $curl_options[CURLOPT_HTTPHEADER] = $header;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $curl_options);
        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);
        return array(
            'result' => $result,
            'code' => $http_code,
            'content_type' => $content_type
        );
    }
}

class Exception extends \Exception
{
}
