<?php

namespace App\Security;

use App\Entity\Users;
use App\Repository\UsersRepository;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use League\OAuth2\Client\Provider\FacebookUser;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use RuntimeException;

class FacebookAuthenticator extends AbstractSocialAuthenticator
{
    protected string $serviceName = 'facebook';

    /**
     * @param ResourceOwnerInterface $facebookUser
     * @param UsersRepository $usersRepository
     * @return Users|null
     * @throws NonUniqueResultException
     * @throws ORMException
     * @throws OptimisticLockException
     */
    protected function getUserFromResourceOwner(
        ResourceOwnerInterface $facebookUser,
        UsersRepository $usersRepository
    ): ?Users
    {
        if (!($facebookUser instanceof FacebookUser)) {
            throw new RuntimeException('Expecting FacebookClient as the first parameter');
        }

        $user = $usersRepository->findForOauth(
            'facebook',
            $facebookUser->getId(),
            $facebookUser->getEmail())
        ;

        if ($user && null === $user->getFacebookId()) {
            $user->setFacebookId($facebookUser->getId());
            $this->entityManager->flush();
        }

        $user = $usersRepository->createForOauth(
            'facebook',
            $facebookUser->getId(),
            $facebookUser->getEmail()
        );

        return $user;
    }
}
