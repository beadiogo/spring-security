package spring.security.login.auth.api.domain.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Entidade que representa um usuário no sistema.
 */
@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
public class User {

    /**
     * Identificador único do usuário.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /**
     * Nome do usuário.
     */
    private String name;

    /**
     * Endereço de e-mail do usuário.
     */
    private String email;

    /**
     * Senha do usuário (geralmente criptografada).
     */
    private String password;
}
