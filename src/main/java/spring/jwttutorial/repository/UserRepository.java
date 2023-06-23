package spring.jwttutorial.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import spring.jwttutorial.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // username으로 User, Authority 같이 조회 (페치조인)
    @EntityGraph(attributePaths = "authorities")
    Optional<User> findOneWithAuthoritiesByUsername(String username);

}
