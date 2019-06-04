<?php
/** Copyright © 2019, Okta, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the 'License');
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an 'AS IS' BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

$jwt = new OktaSimpleJWTVerifier("eyJraWQiOiJfbTE0cC02emlzY3Vfd2RUekM4VmlKRDNBSTl1VU9qT3pDSHllMjNLcVF3IiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULlNid2ZReGNHQm5WVVFPTEN0bTg5S2RaUkJDeW9NOXBBRVZlLUwyWFpWeG8iLCJpc3MiOiJodHRwczovL2RyYWdvcy5va3RhcHJldmlldy5jb20vb2F1dGgyL2F1c2w2dG80NHkyNkp0eUdQMGg3IiwiYXVkIjoiaHR0cHM6Ly9kZXYub2t0YS5hZG1pbnBhbmVsLmJpeiIsImlhdCI6MTU1OTY1NTgzNSwiZXhwIjoxNTU5NjU5NDM1LCJjaWQiOiIwb2FsNnA4emdxT2VhTDg1QzBoNyIsInVpZCI6IjAwdWVheThqY2Q1a2tNV3MyMGg3Iiwic2NwIjpbIm9wZW5pZCIsInByb2ZpbGUiXSwic3ViIjoiZHJhZ29zLmdhZnRvbmVhbnVAZ21haWwuY29tIn0.EamQpMdyei-Zf-4NwbFHCoHfK8UncYFuvK5w-TpQIPdSVBsgxHqoQr_Ez5GqURniNKvt-XT4ZF2CAcSrW17R2Gdjyls7vXCyDWRKCV4D06a9qGXDdvxmkLJgzF5bE3d3TV3DHlqtts69IHDVugPZvYQRnSPaWG6MJFl2Sz80W38Quj0IUupz4AdSL-eUCB5gZkNbf73e0dwUO59MRGG_g_RGkZyyLROo_TwxMyXdTZiIqKeLCW-XA8KDn64DgJQydKTKRlFO4YXU1vLvK4qpCvi6JJf0zvqDKBt_KH9jBaM8qNLIOjB6ppzpCa6s7OrRSLNymhvAF_3IvTUKXOfxEg");

if($jwt->verify())
	echo "JWT has been successfully verified.";
else
	echo $jwt->getError();

class OktaSimpleJWTVerifier
{
	protected $jwt, $audience = "", $clientId = "", $issuer = "", $error = "", $pem = "";
	
	public function __construct($jwt)
	{
		$this->jwt = $jwt;
	}
	
	public function setAudience($audience)
	{
		$this->audience = $audience;
	}
	
	public function setClientId($clientId)
	{
		$this->clientId = $clientId;
	}
	
	public function setIssuer($issuer)
	{
		$this->issuer = $issuer;
	}
	
	public function setPem($pem)
	{
		$this->pem = $pem;
	}
	
	public function verify()
	{
		if(!stristr($this->jwt, "."))
		{
			$this->error = "ERROR: The JWT provided does not contain a delimiter between header, payload and signature.";
			return false;
		}
		
		$part = explode(".",$this->jwt);
		
		if(count($part)!=3)
		{
			$this->error = "ERROR: The JWT provided does not contain the expected structure.";
			return false;
		}
		
		$head = json_decode(base64_decode($part[0]),1);
		$body = json_decode(base64_decode($part[1]),1);
		
		if($head['alg'] != "RS256")
		{
			$this->error = "ERROR: The JWT token is generated through an unsupported algorithm.";
			return false;
		}
		
		if($body['iat'] > time())
		{
			$this->error = "ERROR: The JWT was issued in the future.";
			return false;
		}
		
		if($body['exp'] < time())
		{
			$this->error = "ERROR: The JWT is expired.";
			return false;
		}
		
		if($this->audience != "")
			if($this->audience != $body['aud'])
			{
				$this->error = "ERROR: The JWT does not contain the expected audience.";
				return false;
			}

		if($this->clientId != "")
			if($this->clientId != $body['cid'])
			{
				$this->error = "ERROR: The JWT does not contain the expected client ID.";
				return false;
			}	
		
		if($this->issuer != "")
			if($this->issuer != $body['iss'])
			{
				$this->error = "ERROR: The JWT does not contain the expected issuer.";
				return false;
			}		
		
		$keys = json_decode(file_get_contents(json_decode(file_get_contents($body['iss'] . "/.well-known/openid-configuration"),1)['jwks_uri']),1)['keys'];
		
		foreach($keys as $key)
		{
			$kid_exists = 0;
			if($key['kid'] == $head['kid'])
			{
				$kid_exists = 1;
				if($this->pem != "")
					$pem = $this->pem;
				else
					$pem = $this->createPemFromModulusAndExponent($key['n'], $key['e']);
				break;
			}
		}
		
		if($kid_exists == 0)
			$this->error = "ERROR: The signing key for the token was not found under /keys endpoint.";
		
		if(openssl_verify($part[0] . "." . $part[1], $this->urlsafeB64Decode($part[2]), $pem, OPENSSL_ALGO_SHA256))
		{
			return true;
		}else{
			$this->error = "ERROR: The signature could not be verified.";
			return false;
		}
	}
	
	public function getError()
	{
		return $this->error;
	}

    public function createPemFromModulusAndExponent($n, $e)
    {
        $modulus = $this->urlsafeB64Decode($n);
        $publicExponent = $this->urlsafeB64Decode($e);
        $components = array(
            'modulus' => pack('Ca*a*', 2, $this->encodeLength(strlen($modulus)), $modulus),
            'publicExponent' => pack('Ca*a*', 2, $this->encodeLength(strlen($publicExponent)), $publicExponent)
        );
        $RSAPublicKey = pack(
            'Ca*a*a*',
            48,
            $this->encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );

        $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); 
        $RSAPublicKey = chr(0) . $RSAPublicKey;
        $RSAPublicKey = chr(3) . $this->encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;
        $RSAPublicKey = pack(
            'Ca*a*',
            48,
            $this->encodeLength(strlen($rsaOID . $RSAPublicKey)),
            $rsaOID . $RSAPublicKey
        );
        $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($RSAPublicKey), 64) .
            '-----END PUBLIC KEY-----';
        return $RSAPublicKey;
    }

    private function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
	
    private function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }
        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }
}