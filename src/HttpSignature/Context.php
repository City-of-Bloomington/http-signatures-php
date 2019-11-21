<?php
/**
 * @copyright 2019 City of Bloomington, Indiana
 * @license http://www.gnu.org/licenses/agpl.txt GNU/AGPL, see LICENSE
 */
declare (strict_types=1);

namespace COB\HttpSignature;
use Psr\Http\Message\RequestInterface;

class Context
{
    private $keys;

    /**
     * @param array $keys    An associative array of keyIds and their secrets
     * @param array $headers An array of HTTP header names to include in the signature
     */
    public function __construct(array $keys)
    {
        $this->keys = $keys;
    }

    /**
     * @param RequestInterface $request
     * @param string           $keyId
     * @param string           $algorithm
     * @param array            $http_headers  Request headers to add to the signature
     */
    public function sign(RequestInterface $request,
                         string           $keyId,
                         string           $algorithm,
                         array            $http_headers): RequestInterface
    {
        $special   = ['(request-target)' => strtolower($request->getMethod()).' '.$request->getRequestTarget(),
                      '(created)'        => time()];
        $headers   = array_merge($special, $this->prepareHttpHeaders($request, $http_headers));
        $string    = self::stringToSign($headers);
        $hash      = self::createHash($algorithm, $string, $this->keys[$keyId]);
        $signature = self::formatSignatureParameters([
            'keyId'     => $keyId,
            'algorithm' => $algorithm,
            'created'   => $headers['(created)'],
            'headers'   => implode(' ', array_keys($headers)),
            'signature' => $hash
        ]);
        return $request->withHeader('Signature', $signature)
                       ->withHeader('Authorization', "Signature: $signature");
    }

    public function verify(RequestInterface $request): bool
    {
        if ($request->hasHeader('Authorization')) {
            $signature    = substr($request->getHeader('Authorization')[0], 11);
            $params       = self::parseSignatureParameters($signature);
            $special      = ['(request-target)' => strtolower($request->getMethod()).' '.$request->getRequestTarget(),
                             '(created)'        => $params['created']];
            $http_headers = array_diff($params['headers'], array_keys($special));
            $headers      = array_merge($special, $this->prepareHttpHeaders($request, $http_headers));
            $string       = self::stringToSign($headers);
            $hash         = self::createHash($params['algorithm'], $string, $this->keys[$params['keyId']]);

            return $hash == $params['signature'];
        }
        return false;
    }

    private function createHash(string $algorithm, string $stringToSign, string $secret): string
    {
        if (substr($algorithm, 0, 4) == 'hmac') {
            $algo = substr($algorithm, 5);
            return base64_encode(hash_hmac($algo, $stringToSign, $secret));
        }

        throw new \Exception('unsupportedAlgorithm');
    }

    private function prepareHttpHeaders(RequestInterface $request, array $http_headers): array
    {
        foreach ($http_headers as $k) {
            $v = implode(', ', $request->getHeader($k));
            $headers[strtolower($k)] = $v;
        }
        return $headers;
    }

    private static function stringToSign(array $headers): string
    {
        $string = '';
        foreach ($headers as $k=>$v) { $string.="$k: $v\n"; }
        return trim($string);
    }

    private static function formatSignatureParameters(array $params): string
    {
        $s = [];
        foreach ($params as $k=>$v) { $s[] = "$k=\"$v\""; }
        return implode(',', $s);
    }

    private static function parseSignatureParameters(string $signature): array
    {
        $params = [];
        foreach(explode(',', $signature) as $p) {
            if (preg_match('/(.+)="(.+)"/', $p, $matches)) {
                $params[$matches[1]] = $matches[1]=='headers'
                                     ? explode(' ', $matches[2])
                                     : $matches[2];
            }
        }
        return $params;
    }
}
