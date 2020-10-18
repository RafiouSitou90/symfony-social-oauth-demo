<?php

namespace App\Security;

use App\Entity\Users;
use App\Repository\UsersRepository;
use App\Security\Exception\UserOauthNotFoundException;
use Doctrine\ORM\EntityManagerInterface;
use Exception;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2Client;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * Class AbstractSocialAuthenticator
 * @package App\Security
 */
class AbstractSocialAuthenticator extends SocialAuthenticator
{

    use TargetPathTrait;

    /**
     * @var string
     */
    protected string $serviceName = '';

    /**
     * @var RouterInterface
     */
    private RouterInterface $router;

    /**
     * @var ClientRegistry
     */
    private ClientRegistry $clientRegistry;

    /**
     * @var EntityManagerInterface
     */
    protected EntityManagerInterface $entityManager;

    /**
     * AbstractSocialAuthenticator constructor.
     * @param RouterInterface $router
     * @param ClientRegistry $clientRegistry
     * @param EntityManagerInterface $entityManager
     */
    public function __construct(
        RouterInterface $router,
        ClientRegistry $clientRegistry,
        EntityManagerInterface $entityManager
    )
    {
        $this->router = $router;
        $this->clientRegistry = $clientRegistry;
        $this->entityManager = $entityManager;
    }

    /**
     * @param Request $request
     * @return bool
     * @throws Exception
     */
    public function supports(Request $request)
    {
        if ('' === $this->serviceName) {
            throw new Exception("You must set a \$serviceName property (for instance 'github', 'facebook')");
        }

        return 'oauth_check'
            === $request->attributes->get('_route')
            && $request->get('service') === $this->serviceName
        ;
    }

    /**
     * @param Request $request
     * @param AuthenticationException|null $authException
     * @return RedirectResponse|Response
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new RedirectResponse($this->router->generate('app_login'));
    }

    /**
     * @param Request $request
     * @return AccessToken|mixed
     */
    public function getCredentials(Request $request)
    {
        return $this->fetchAccessToken($this->getClient());
    }

    /**
     * @param AccessToken $credentials
     * @param UserProviderInterface $userProvider
     * @return Users|UserInterface|null
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $resourceOwner = $this->getResourceOwnerFromCredentials($credentials);
        $usersRepository = $this->entityManager->getRepository(Users::class);

        $user = $this->getUserFromResourceOwner($resourceOwner, $usersRepository);
        if (null === $user) {
            throw new UserOauthNotFoundException($resourceOwner);
        }

        return $user;
    }

    /**
     * @param Request $request
     * @param AuthenticationException $exception
     * @return RedirectResponse|Response|null
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($request->hasSession()) {
            $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
        }

        return new RedirectResponse($this->router->generate('app_login'));
    }

    /**
     * @param Request $request
     * @param TokenInterface $token
     * @param string $providerKey
     * @return RedirectResponse|Response|null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $providerKey)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->router->generate('app_home_index'));
    }

    /**
     * @param AccessToken $credentials
     * @return ResourceOwnerInterface
     */
    protected function getResourceOwnerFromCredentials(AccessToken $credentials): ResourceOwnerInterface
    {
        return $this->getClient()->fetchUserFromToken($credentials);
    }

    /**
     * @param ResourceOwnerInterface $resourceOwner
     * @param UsersRepository $usersRepository
     * @return Users|null
     */
    protected function getUserFromResourceOwner(
        ResourceOwnerInterface $resourceOwner,
        UsersRepository $usersRepository
    ): ?Users
    {
        return null;
    }

    /**
     * @return OAuth2Client
     */
    protected function getClient(): OAuth2Client
    {
        /** @var OAuth2Client $client */
        $client = $this->clientRegistry->getClient($this->serviceName);

        return $client;
    }
}
