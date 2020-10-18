<?php

namespace App\Security;

use App\Entity\Users;
use App\Repository\UsersRepository;
use App\Security\Exception\EmailAlreadyUsedException;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use League\OAuth2\Client\Provider\FacebookUser;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use RuntimeException;

/**
 * Class FacebookAuthenticator
 * @package App\Security
 */
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
            $this->serviceName,
            $facebookUser->getId(),
            $facebookUser->getEmail())
        ;

        if ($user) {
            if (strtolower($facebookUser->getEmail()) === $user->getEmail()
                && $user->getFacebookId() !== (string) $facebookUser->getId()
            ) {
                throw new EmailAlreadyUsedException();
            }

            if (null === $user->getFacebookId()) {
                $user->setFacebookId($facebookUser->getId());
                $this->entityManager->flush();

                return $user;
            } else if ($user->getFacebookId() === (string) $facebookUser->getId()) {

                return $user;
            }
        }

        $user = $usersRepository->createForOauth(
            $this->serviceName,
            $facebookUser->getId(),
            $facebookUser->getEmail()
        );

        return $user;
    }
}
