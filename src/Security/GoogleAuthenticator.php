<?php

namespace App\Security;

use App\Entity\Users;
use App\Repository\UsersRepository;
use App\Security\Exception\EmailAlreadyUsedException;
use App\Security\Exception\NotVerifiedEmailException;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use RuntimeException;

class GoogleAuthenticator extends AbstractSocialAuthenticator
{
    protected string $serviceName = 'google';

    /**
     * @param ResourceOwnerInterface $googleUser
     * @param UsersRepository $usersRepository
     * @return Users|null
     * @throws NonUniqueResultException
     * @throws ORMException
     * @throws OptimisticLockException
     */
    public function getUserFromResourceOwner(
        ResourceOwnerInterface $googleUser,
        UsersRepository $usersRepository
    ): ?Users
    {
        if (!($googleUser instanceof GoogleUser)) {
            throw new RuntimeException('Expecting GoogleUser as the first parameter');
        }
        if (true !== ($googleUser->toArray()['email_verified'] ?? null)) {
            throw new NotVerifiedEmailException();
        }

        $user = $usersRepository->findForOauth(
            'google',
            $googleUser->getId(),
            $googleUser->getEmail())
        ;

        if ($user) {
            if (strtolower($googleUser->getEmail()) === $user->getEmail()
                && $user->getGoogleId() !== (string) $googleUser->getId()
            ) {
                throw new EmailAlreadyUsedException();
            }

            if (null === $user->getGoogleId()) {
                $user->setGoogleId($googleUser->getId());
                $this->entityManager->flush();

                return $user;
            } else if ($user->getGoogleId() === (string) $googleUser->getId()) {

                return $user;
            }
        }

        $user = $usersRepository->createForOauth(
            'google',
            $googleUser->getId(),
            $googleUser->getEmail()
        );

        return $user;
    }
}
