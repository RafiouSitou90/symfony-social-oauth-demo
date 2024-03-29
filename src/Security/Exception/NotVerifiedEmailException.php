<?php

namespace App\Security\Exception;

use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Throwable;

/**
 * Class NotVerifiedEmailException
 * @package App\Security\Exception
 */
class NotVerifiedEmailException extends CustomUserMessageAuthenticationException
{
    /**
     * NotVerifiedEmailException constructor.
     * @param string $message
     * @param array $messageData
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct(
        string $message = 'This account does not appear to have a verified email',
        array $messageData = [],
        int $code = 0,
        Throwable $previous = null
    )
    {
        parent::__construct($message, $messageData, $code, $previous);
    }
}
