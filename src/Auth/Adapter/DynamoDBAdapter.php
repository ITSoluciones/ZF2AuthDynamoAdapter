<?php
/**
 * ITSoluciones EIRL
 * ZF2 Auth Adapter with AWS DynamoDB.
 *
 * @license		MIT
 * @copyright	Copyright (c) 2013 ITSoluciones E.I.R.L.
 * @link		http://www.itsoluciones.cl
 * @version		1.0.0
 * @package		ITSoluciones\Auth\Adapter
 */

namespace ITSoluciones\Auth\Adapter;

use Zend\Authentication\Adapter\Exception;
use Zend\Authentication\Adapter\AdapterInterface;
use Zend\Authentication\Result;

use Aws\DynamoDb\DynamoDbClient;
use Aws\DynamoDb\Marshaler;

class DynamoDBAdapter implements AdapterInterface
{
	private $email;
	private $password;
	private $db;
	private $secret;

	/**
     * Sets email and password for authentication
     * Sets db and secret for Dynamo connection and hash_hmac
     *
     * @return void
     */
	public function __construct($email, $password, $db, $secret)
	{
		$this->email 		= $email;
		$this->password 	= $password;
		$this->db			= $db;
		$this->secret		= $secret;
	}

    /**
     * Performs an authentication attempt
     *
     * @return \Zend\Authentication\Result
     * @throws \Zend\Authentication\Adapter\Exception\ExceptionInterface
     *               If authentication cannot be performed
     */
	public function authenticate()
    {
		$client = new DynamoDbClient($this->db);
		$result = $client->getItem(array(
		    'ConsistentRead' => true,
		    'TableName' => $this->secret . '.users',
		    'Key'       => array(
		        'email'   => array('S' => $this->email)
		    )
		));

		$marshaler	= new Marshaler();
		if($result['Item'] != null){
			$data = $marshaler->unmarshalItem($result['Item']);
		}else{
			return new Result(Result::FAILURE, null, ['El email ingresado no se encuentra registrado.']);
		}

		if($data['loginProvider'] != 'db')
			return new Result(Result::FAILURE, $data, ['LoginProvider no corresponde.']);

		if($data['email'] === '')
			return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $data, ['El email ingresado no se encuentra registrado.']);

		if($data['password'] != hash_hmac('sha256', $this->password, $this->secret))
			return new Result(Result::FAILURE_CREDENTIAL_INVALID, $data, ['El password ingresado no es correcto.']);

		return new Result(Result::SUCCESS, $data);
    }
}