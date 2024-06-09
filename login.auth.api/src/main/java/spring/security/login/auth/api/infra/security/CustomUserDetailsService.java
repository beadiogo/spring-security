package spring.security.login.auth.api.infra.security;

import spring.security.login.auth.api.domain.user.User;
import spring.security.login.auth.api.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

/**
 * Serviço personalizado para carregar detalhes do usuário durante a autenticação.
 * Esta classe implementa a interface UserDetailsService do Spring Security.
 */
@Component
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    /**
     * Carrega os detalhes do usuário com base no nome de usuário (email).
     * @param username O nome de usuário (email) do usuário cujos detalhes devem ser carregados.
     * @return UserDetails contendo os detalhes do usuário, se encontrado.
     * @throws UsernameNotFoundException Se o usuário com o nome de usuário fornecido não for encontrado.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = this.repository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), new ArrayList<>());
    }
}
