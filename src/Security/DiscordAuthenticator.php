<?php

namespace App\Security;

use App\Entity\Users;
use App\Repository\UsersRepository;
use App\Security\Exception\EmailAlreadyUsedException;
use App\Security\Exception\NotVerifiedEmailException;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use RuntimeException;
use Wohali\OAuth2\Client\Provider\DiscordResourceOwner;

/**
 * Class DiscordAuthenticator
 * @package App\Security
 */
class DiscordAuthenticator extends AbstractSocialAuthenticator
{
    protected string $serviceName = 'discord';

    /**
     * @param ResourceOwnerInterface $discordUser
     * @param UsersRepository $usersRepository
     * @return Users|null
     * @throws NonUniqueResultException
     * @throws ORMException
     * @throws OptimisticLockException
     */
    protected function getUserFromResourceOwner(
        ResourceOwnerInterface $discordUser,
        UsersRepository $usersRepository
    ): ?Users
    {
        if (!($discordUser instanceof DiscordResourceOwner)) {
            throw new RuntimeException('Expecting DiscordResourceOwner as the first parameter');
        }
        if (true !== ($discordUser->toArray()['verified'] ?? null)) {
            throw new NotVerifiedEmailException();
        }

        $user = $usersRepository->findForOauth(
            $this->serviceName,
            $discordUser->getId(),
            $discordUser->getEmail())
        ;

        if ($user) {
            if (strtolower($discordUser->getEmail()) === $user->getEmail()
                && $user->getDiscordId() !== (string) $discordUser->getId()
            ) {
                throw new EmailAlreadyUsedException();
            }

            if (null === $user->getDiscordId()) {
                $user->setDiscordId($discordUser->getId());
                $this->entityManager->flush();

                return $user;
            } else if ($user->getDiscordId() === (string) $discordUser->getId()) {

                return $user;
            }
        }

        $user = $usersRepository->createForOauth(
            $this->serviceName,
            $discordUser->getId(),
            $discordUser->getEmail()
        );

        return $user;
    }
}
