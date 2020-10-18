<?php

namespace App\Security;

use App\Entity\Users;
use App\Repository\UsersRepository;
use App\Security\Exception\EmailAlreadyUsedException;
use App\Security\Exception\NotVerifiedEmailException;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use RuntimeException;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;

/**
 * Class GithubAuthenticator
 * @package App\Security
 */
class GithubAuthenticator extends AbstractSocialAuthenticator
{

    protected string $serviceName = 'github';

    /**
     * @param ResourceOwnerInterface $githubUser
     * @param UsersRepository $usersRepository
     * @return Users|null
     * @throws NonUniqueResultException
     * @throws ORMException
     * @throws OptimisticLockException
     */
    protected function getUserFromResourceOwner(
        ResourceOwnerInterface $githubUser,
        UsersRepository $usersRepository
    ): ?Users
    {
        if (!($githubUser instanceof GithubResourceOwner)) {
            throw new RuntimeException('Expecting GithubResourceOwner as the first parameter');
        }

        $user = $usersRepository->findForOauth(
            'github',
            $githubUser->getId(),
            $githubUser->getEmail())
        ;

        if ($user) {
            if (strtolower($githubUser->getEmail()) === $user->getEmail()
                && $user->getGithubId() !== (string) $githubUser->getId()
            ) {
                throw new EmailAlreadyUsedException();
            }

            if (null === $user->getGithubId()) {
                $user->setGithubId($githubUser->getId());
                $this->entityManager->flush();

                return $user;
            } else if ($user->getGithubId() === (string) $githubUser->getId()) {

                return $user;
            }
        }

        $user = $usersRepository->createForOauth(
            'github',
            $githubUser->getId(),
            $githubUser->getEmail()
        );

        return $user;
    }

    /**
     * @param AccessToken $credentials
     * @return GithubResourceOwner
     * @throws ClientExceptionInterface
     * @throws RedirectionExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    public function getResourceOwnerFromCredentials(AccessToken $credentials): GithubResourceOwner
    {
        /** @var GithubResourceOwner $githubUser */
        $githubUser = parent::getResourceOwnerFromCredentials($credentials);
        $response = HttpClient::create()->request(
            'GET',
            'https://api.github.com/user/emails',
            [
                'headers' => [
                    'authorization' => "token {$credentials->getToken()}",
                ],
            ]
        );
        $emails = json_decode($response->getContent(), true);
        foreach ($emails as $email) {
            if (true === $email['primary'] && true === $email['verified']) {
                $data = $githubUser->toArray();
                $data['email'] = $email['email'];

                return new GithubResourceOwner($data);
            }
        }

        throw new NotVerifiedEmailException();
    }
}
