<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\Provider\DiscordClient;
use KnpU\OAuth2ClientBundle\Client\Provider\FacebookClient;
use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
use KnpU\OAuth2ClientBundle\Client\Provider\GoogleClient;
use LogicException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    /**
     * @Route("/login", name="app_login")
     * @param AuthenticationUtils $authenticationUtils
     * @return Response|RedirectResponse
     */
    public function login(AuthenticationUtils $authenticationUtils)
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_home_index');
        }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    /**
     * @Route("/connect/github", name="app_github_connect")
     * @param ClientRegistry $clientRegistry
     * @return RedirectResponse
     */
    public function github_connect(ClientRegistry $clientRegistry): RedirectResponse
    {
        /** @var GithubClient $client */
        $client = $clientRegistry->getClient('github');
        return $client->redirect(['read:user', 'user:email']);
    }

    /**
     * @Route("/connect/facebook", name="app_facebook_connect")
     * @param ClientRegistry $clientRegistry
     * @return RedirectResponse
     */
    public function facebook_connect(ClientRegistry $clientRegistry): RedirectResponse
    {
        /** @var FacebookClient $client */
        $client = $clientRegistry->getClient('facebook');

        return $client->redirect(['email']);
    }

    /**
     * @Route("/connect/google", name="app_google_connect")
     * @param ClientRegistry $clientRegistry
     * @return RedirectResponse
     */
    public function google_connect(ClientRegistry $clientRegistry): RedirectResponse
    {
        /** @var GoogleClient $client */
        $client = $clientRegistry->getClient('google');

        return $client->redirect(['profile', 'email']);
    }

    /**
     * @Route("/connect/discord", name="app_discord_connect")
     * @param ClientRegistry $clientRegistry
     * @return RedirectResponse
     */
    public function discord_connect(ClientRegistry $clientRegistry): RedirectResponse
    {
        /** @var DiscordClient $client */
        $client = $clientRegistry->getClient('discord');

        return $client->redirect(['identify', 'email']);
    }

    /**
     * @Route("/logout", name="app_logout")
     * @return void
     */
    public function logout()
    {
        throw new LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}
