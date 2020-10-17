<?php

namespace App\Security;

use App\Repository\UsersRepository;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Client\Provider\FacebookClient;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class FacebookAuthenticator extends SocialAuthenticator
{

    use TargetPathTrait;

    /**
     * @var RouterInterface
     */
    private RouterInterface $router;
    /**
     * @var ClientRegistry
     */
    private ClientRegistry $clientRegistry;
    /**
     * @var UsersRepository
     */
    private UsersRepository $usersRepository;

    public function __construct(
        RouterInterface $router,
        ClientRegistry $clientRegistry,
        UsersRepository $usersRepository
    )
    {
        $this->router = $router;
        $this->clientRegistry = $clientRegistry;
        $this->usersRepository = $usersRepository;
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new RedirectResponse($this->router->generate('app_login'));
    }

    public function supports(Request $request)
    {
        return 'oauth_check' === $request->attributes->get('_route') && $request->get('service') === 'facebook';
    }

    public function getCredentials(Request $request)
    {
        return $this->fetchAccessToken($this->getClient());
    }

    /**
     * @param AccessToken $credentials
     * @param UserProviderInterface $userProvider
     * @return UserInterface|void|null
     * @throws NonUniqueResultException
     * @throws ORMException
     * @throws OptimisticLockException
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $facebookUser = $this->getClient()->fetchUserFromToken($credentials);

        return $this->usersRepository->findOrCreateFromFacebookOauthToken($facebookUser);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($request->hasSession()) {
            $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
        }

        return new RedirectResponse($this->router->generate('app_login'));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        $targetPath = $this->getTargetPath($request->getSession(), $providerKey);

        return new RedirectResponse($targetPath ? : '/');
    }

    /**
     * @return OAuth2ClientInterface|FacebookClient
     */
    private function getClient(): FacebookClient
    {
        return $this->clientRegistry->getClient('facebook');
    }
}
