<?php

namespace App\Security\Exception;

use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Throwable;

/**
 * Class EmailAlreadyUsedException
 * @package App\Security\Exception
 */
class EmailAlreadyUsedException extends CustomUserMessageAuthenticationException
{
    /**
     * EmailAlreadyUsedException constructor.
     * @param string $message
     * @param array $messageData
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct(
        string $message = 'An account already exists with this email.',
        array $messageData = [],
        int $code = 0,
        Throwable $previous = null
    )
    {
        parent::__construct($message, $messageData, $code, $previous);
    }
}
