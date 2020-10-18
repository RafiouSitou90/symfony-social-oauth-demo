<?php

namespace App\Repository;

use App\Entity\Users;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use Doctrine\Persistence\ManagerRegistry;
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

//    /**
//     * @param GithubResourceOwner $githubResourceOwner
//     * @return Users
//     * @throws NonUniqueResultException
//     * @throws ORMException
//     * @throws OptimisticLockException
//     */
//    public function findOrCreateFromGithubOauthToken(GithubResourceOwner $githubResourceOwner): Users
//    {
//        /** @var Users|null $user */
//        $user = $this->createQueryBuilder('u')
//            ->where('u.githubId = :githubId')
//            ->orWhere('u.email = :email')
//            ->setParameters([
//                'githubId' => $githubResourceOwner->getId(),
//                'email' => $githubResourceOwner->getEmail()
//            ])
//            ->getQuery()
//            ->getOneOrNullResult()
//        ;
//
//        if ($user) {
//            if ($user->getGithubId() === null) {
//                $user->setGithubId($githubResourceOwner->getId());
//                $this->getEntityManager()->flush();
//            }
//            return $user;
//        }
//
//        $user = (new Users())
//            ->setGithubId($githubResourceOwner->getId())
//            ->setUsername($githubResourceOwner->getEmail())
//            ->setEmail($githubResourceOwner->getEmail())
//        ;
//
//        $entityManager = $this->getEntityManager();
//        $entityManager->persist($user);
//        $entityManager->flush();
//
//        return $user;
//    }

//    /**
//     * @param FacebookUser $facebookUser
//     * @return Users
//     * @throws NonUniqueResultException
//     * @throws ORMException
//     * @throws OptimisticLockException
//     */
//    public function findOrCreateFromFacebookOauthToken(FacebookUser $facebookUser): Users
//    {
//        /** @var Users|null $user */
//        $user = $this->createQueryBuilder('u')
//            ->where('u.facebookId = :facebookId')
//            ->orWhere('u.email = :email')
//            ->setParameters([
//                'facebookId' => $facebookUser->getId(),
//                'email' => $facebookUser->getEmail(),
//            ])
//            ->getQuery()
//            ->getOneOrNullResult()
//        ;
//
//        if ($user) {
//            if ($user->getFacebookId() === null) {
//                $user->setFacebookId($facebookUser->getId());
//                $this->getEntityManager()->flush();
//            }
//            return $user;
//        }
//
//        $user = (new Users())
//            ->setFacebookId($facebookUser->getId())
//            ->setUsername($facebookUser->getEmail())
//            ->setEmail($facebookUser->getEmail())
//        ;
//
//        $entityManager = $this->getEntityManager();
//        $entityManager->persist($user);
//        $entityManager->flush();
//
//        return $user;
//    }

    /**
     * @param string $serviceName
     * @param string|null $serviceId
     * @param string|null $email
     * @return Users|null
     * @throws NonUniqueResultException
     */
    public function findForOauth(string $serviceName, ?string $serviceId = null, ?string $email = null): ?Users
    {
        if (null === $serviceId || null === $email) {
            return null;
        }

        return $this->createQueryBuilder('u')
            ->where("u.{$serviceName}Id = :serviceId")
            ->orWhere('u.email = :email')
            ->setMaxResults(1)
            ->setParameters([
                'serviceId' => $serviceId,
                'email' => strtolower($email),
            ])
            ->getQuery()
            ->getOneOrNullResult()
        ;
    }

    /**
     * @param string $serviceName
     * @param string $serviceId
     * @param string $email
     * @return Users
     * @throws ORMException
     * @throws OptimisticLockException
     */
    public function createForOauth(
        string $serviceName,
        string $serviceId,
        string $email
    ): Users
    {
        $serviceIdSetter = 'set' . ucfirst($serviceName) . 'Id';
        $user = (new Users())
            ->$serviceIdSetter($serviceId)
            ->setUsername(strtolower($email))
            ->setEmail(strtolower($email))
        ;

        $entityManager = $this->getEntityManager();
        $entityManager->persist($user);
        $entityManager->flush();

        return $user;
    }
}
