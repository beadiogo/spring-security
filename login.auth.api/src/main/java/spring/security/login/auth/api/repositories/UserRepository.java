package spring.security.login.auth.api.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.login.auth.api.domain.user.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmail(String email);
}
