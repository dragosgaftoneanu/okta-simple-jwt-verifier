# Okta Simple JWT Verifier
Okta Simple JWT Verifier is a simple stand-alone SDK that can be used to verify JWT tokens issued by Okta orgs.

:warning: **Disclaimer:** This is not an official product and does not qualify for Okta Support.

## Installation
You can install this SDK by running the following command through Composer

```
composer require dragosgaftoneanu/okta-simple-jwt-verifier
```

## Requirements
* An Okta account, called an _organization_ (you can sign up for a free [developer organization](https://developer.okta.com/signup/))
* A local web server that runs PHP 7.0+

## Methods available
### setAudience($audience)
This method sets an audience to be checked in the JWT token.

### setClientId($clientId)
This method sets a client ID to be checked inside `cid` claim, which is present in access tokens.

### setIssuer($issuer)
This method sets an issuer to be checked in the JWT token.

### setPem($pem)
This method sets the public key that will be used to check the JWT token. This is useful when you want to verify against a locally saved key.

### setNonce($nonce)
This method sets a nonce to be checked in the JWT token.

### verify()
This method verifies the following details inside a JWT token:
* algorithm inside header to be set to RS256 (the current supported algorithm)
* issued time to not be in the future (rare cases in which the time of the server is not alligned correctly to UTC timezone)
* expiration time to not be in the past (in this case, the token provided would be expired)
* audience claim (if `setAudience($audience)` was added previously)
* client ID claim (if `setClientId($clientId)` was added previously)
* issuer claim (if `setIssuer($issuer)` was added previously)
* nonce claim (if `setNonce($nonce)` was added previously)
* signature

The result of this method is an array containing the body of the JWT token sent for verification.

### createPemFromModulusAndExponent($n, $e)
This method creates the public key from modulus and exponent present on /keys endpoint.

## Example
The following example takes a JWT token, verifies it and, based on the response, it returns a feedback.

```php
use Okta\SimpleJWTVerifier\SimpleJWTVerifier;

try{
	$jwt = new SimpleJWTVerifier("eyJraWQiOiJkbUhnMjRzNDdnWXZ6bE5JWTFmMFJxWVdrb2VQQ2R0WmdVdnRxdnNzeTRVIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULkU2OUFHdVZPYmRsYzlkY2J1WHZ4MkE5NnR0TVRhajZqX1JWMXVORDI5SW8iLCJpc3MiOiJodHRwczovL2RyYWdvcy5va3RhLmNvbS9vYXV0aDIvYXVzMzhlbDg4bGZjTDZQRmcycDciLCJhdWQiOiJodHRwczovL2Rldi5va3RhLmFkbWlucGFuZWwuYml6IiwiaWF0IjoxNTYwNzYyODAzLCJleHAiOjE1NjA3NjY0MDMsImNpZCI6IjBvYTJmYXR4NzBKR2lVMlRBMnA3IiwidWlkIjoiMDB1b3piZ2MwM3d6cW9hWHAycDYiLCJzY3AiOlsib3BlbmlkIiwicHJvZmlsZSJdLCJzdWIiOiJ0ZXN0LnVzZXJAb2t0YS5sb2NhbCIsIm9yZyI6InRlc3QifQ.vXowkWk_s-_0M6BZir0KaJSthslu7YWXMa4HsOlAU1xlLCtdC17iiIx1vA5WFiJyNFIkc1ClHdGxbDNpmMUBkKDkJ8fQ81gwt172f8hReeN4ndHEklBpCyQRGXS1by2gooCiMrK8kUCm3gUhaMnnVSZTzyipWlwS7scj8CY2LKAZsUXEnsQSWpmU1fnNoZpsE-1YkLbLXkRSPa2W_-TomnVntx-QZRNLoDl219r3eyGErc21S5pLtESkU4AtgiAHKW87eNrAJ94Lza_3ZlNnciTjDu3d3DLtLlvv6FeRA2eGmubwVAVo0nojWQ7dPUy3IZdayxsYhdhAJu5ZB67YmQ");
	$jwt->setAudience("https://dev.okta.adminpanel.biz");
	$jwt->setClientId("0oa2fatx70JGiU2TA2p7");
	$jwt->setIssuer("https://dragos.okta.com/oauth2/aus38el88lfcL6PFg2p7");
	$result = $jwt->verify();
	print_r($result);
}catch (Exception $e){
	echo $e->getMessage();
}
```
	
The response returned, at the moment of writing the README, will be

```
Array
(
    [ver] => 1
    [jti] => AT.E69AGuVObdlc9dcbuXvx2A96ttMTaj6j_RV1uND29Io
    [iss] => https://dragos.okta.com/oauth2/aus38el88lfcL6PFg2p7
    [aud] => https://dev.okta.adminpanel.biz
    [iat] => 1560762803
    [exp] => 1560766403
    [cid] => 0oa2fatx70JGiU2TA2p7
    [uid] => 00uozbgc03wzqoaXp2p6
    [scp] => Array
        (
            [0] => openid
            [1] => profile
        )

    [sub] => test.user@okta.local
    [org] => test
)
```

## Copyright
This SDK was built based on [okta/okta-jwt-verifier-php](https://github.com/okta/okta-jwt-verifier-php) and [firebase/php-jwt](https://github.com/firebase/php-jwt).

## Bugs?
If you find a bug or encounter an issue when using the SDK, please open an issue on GitHub [here](https://github.com/dragosgaftoneanu/okta-simple-jwt-verifier/issues) and it will be further investigated.