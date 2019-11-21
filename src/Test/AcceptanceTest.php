<?php
/**
 * @copyright 2019 City of Bloomington, Indiana
 * @license http://www.gnu.org/licenses/agpl.txt GNU/AGPL, see LICENSE
 */
declare (strict_types=1);

use HttpSignature\Context;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7;

class AcceptanceTest extends TestCase
{
    protected $keys = ['test' => 'askldjakldjalkjfalskjf'];

    public function testContextValidatesItself()
    {
        $context = new Context($this->keys);
        $request = new Psr7\Request('GET',
                                    'https://somewhere.org/test',
                                    ['username' => 'inghamn']);
        $signed  = $context->sign($request, 'test', 'hmac_sha256', ['username']);
        $this->assertTrue($context->verify($signed));
    }
}
