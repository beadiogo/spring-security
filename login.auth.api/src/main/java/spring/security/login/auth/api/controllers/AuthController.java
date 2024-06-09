package spring.security.login.auth.api.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.security.login.auth.api.domain.user.User;
import spring.security.login.auth.api.dto.LoginRequestDTO;
import spring.security.login.auth.api.dto.RegisterRequestDTO;
import spring.security.login.auth.api.dto.ResponseDTO;
import spring.security.login.auth.api.infra.security.TokenService;
import spring.security.login.auth.api.repositories.UserRepository;

import java.util.Optional;

/**
 * Controlador para autenticação e registro de usuários.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    /**
     * Endpoint para autenticar um usuário.
     * @param body O objeto de solicitação de login contendo e-mail e senha.
     * @return ResponseEntity contendo um token JWT se a autenticação for bem-sucedida, ou um ResponseEntity de erro se falhar.
     */
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO body){
        User user = this.repository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User not found."));
        if(passwordEncoder.matches(body.password(), user.getPassword())){
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getName(),token ));
        }
        return ResponseEntity.badRequest().build();
    }

    /**
     * Endpoint para registrar um novo usuário.
     * @param body O objeto de solicitação de registro contendo e-mail, senha e nome do usuário.
     * @return ResponseEntity contendo um token JWT e informações do usuário registrado se o registro for bem-sucedido, ou um ResponseEntity de erro se falhar.
     */
    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body){
        Optional<User> user = this.repository.findByEmail(body.email());

        if(user.isEmpty()) {
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());
            this.repository.save(newUser);

            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new ResponseDTO(newUser.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }
}

