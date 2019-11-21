# HTTP Signature library for PHP

A library for signing and verifying Psr7 Requests according to the draft
[IETF HTTP Signatures RFC](https://tools.ietf.org/html/draft-cavage-http-signatures).
This library should be up to date with version 12 of the draft.

## Installation
Add this repository to your composer.json and require city-of-bloomington/http-signatures.

```json
{
    "repositories": [{
        "type": "vcs",
        "url": "https://github.com/City-of-Bloomington/blossom-lib"
    }],
    "require": {
        "city-of-bloomington/http-signatures": "@dev-master"
    }
}
```

## Usage
This library provides a Context class that can sign and verify Psr7 requests.
This example uses Guzzle for demonstration purposes, but you can use anything
that implements the Psr7 RequestInterface.

So far, we've only implemented hmac_sha256.  More will be implemented as needed.

```php
declare (strict_types=1);

use COB\HttpSignature\Context;
use GuzzleHttp\Psr7;

$request = new Psr7\Request('GET',
                            BASE_URL.'/users?format=json&username=inghamn',
                            ['X-SpecialHeader' => 'some value']);

$keys    = ['test_key'    => 'asdkljaskldjaskldj',
            'another_key' => 'jkvfioejv909024ujv'];
$context = new Context($keys);
$signed  = $context->sign($request, 'test_key', 'hmac_sha256', ['X-SpecialHeader']);

if ($context->verify($signed)) {
    echo "Verified\n";
}
else {
    echo "Not verified\n";
}

```
