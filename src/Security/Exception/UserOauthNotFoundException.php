<?php

namespace App\Security\Exception;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class UserOauthNotFoundException extends AuthenticationException
{
    private ResourceOwnerInterface $resourceOwner;

    /**
     * UserOauthNotFoundException constructor.
     * @param ResourceOwnerInterface $resourceOwner
     */
    public function __construct(ResourceOwnerInterface $resourceOwner)
    {
        $this->resourceOwner = $resourceOwner;
    }

    /**
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(): ResourceOwnerInterface
    {
        return $this->resourceOwner;
    }
}
