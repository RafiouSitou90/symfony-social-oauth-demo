<?php

namespace App\Repository;

use App\Entity\Users;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use Doctrine\Persistence\ManagerRegistry;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use function get_class;

/**
 * @method Users|null find($id, $lockMode = null, $lockVersion = null)
 * @method Users|null findOneBy(array $criteria, array $orderBy = null)
 * @method Users[]    findAll()
 * @method Users[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class UsersRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Users::class);
    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     * @param UserInterface $user
     * @param string $newEncodedPassword
     * @throws ORMException
     * @throws OptimisticLockException
     */
    public function upgradePassword(UserInterface $user, string $newEncodedPassword): void
    {
        if (!$user instanceof Users) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        $user->setPassword($newEncodedPassword);
        $this->_em->persist($user);
        $this->_em->flush();
    }

    /**
     * @param string $username
     * @return Users|null
     * @throws NonUniqueResultException
     */
    public function findOneByUsernameOrEmail(string $username): ?Users
    {
        return $this->createQueryBuilder('u')
            ->where('u.username = :param_username OR u.email = :param_email')
            ->setParameter('param_username', $username)
            ->setParameter('param_email', $username)
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * @param GithubResourceOwner $githubResourceOwner
     * @return Users
     * @throws NonUniqueResultException
     * @throws ORMException
     * @throws OptimisticLockException
     */
    public function findOrCreateFromGithubOauthToken(GithubResourceOwner $githubResourceOwner): Users
    {
        /** @var Users|null $user */
        $user = $this->createQueryBuilder('u')
            ->where('u.githubId = :githubId')
            ->orWhere('u.username = :username')
            ->orWhere('u.email = :email')
            ->setParameters([
                'githubId' => $githubResourceOwner->getId(),
                'username' => $githubResourceOwner->getNickname(),
                'email' => $githubResourceOwner->getEmail()
            ])
            ->getQuery()
            ->getOneOrNullResult()
        ;

        if ($user) {
            if ($user->getGithubId() === null) {
                $user->setGithubId($githubResourceOwner->getId());
                $this->getEntityManager()->flush();
            }
            return $user;
        }

        $user = (new Users())
            ->setGithubId($githubResourceOwner->getId())
            ->setUsername($githubResourceOwner->getNickname())
            ->setEmail($githubResourceOwner->getEmail())
        ;

        $entityManager = $this->getEntityManager();
        $entityManager->persist($user);
        $entityManager->flush();

        return $user;
    }
}
