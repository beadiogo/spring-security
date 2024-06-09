# Projeto - Spring Security em Programação Orientada a Objetos.

Neste tutorial, vamos descrever como configurar o Spring Security em um projeto Spring Boot para realizar autenticação com nome de usuário, senha e token. Vamos começar com um novo projeto criado utilizando o Spring Initializr e incluir as dependências necessárias.

## Criando um Projeto com Spring Initializr

Para começar, vamos criar um novo projeto utilizando o Spring Initializr. Certifique-se de incluir as seguintes dependências:

- [x] Spring Web
- [x] JPA
- [x] Spring Security
- [x] Spring Boot Dev Tools
- [x] Lombok

Agora, vamos aos passos para configurar o Spring Security.

## Configurando o Spring Security

1. **Adicionar as Dependências H2 Database (Banco de Dados Relacional) e JWT(padrão aberto para criar tokens de acesso)**: Adicionar as dependências no arquivo `pom.xml` abaixo das última dependência já presente no arquivo:
- Copiar e colar: 
```xml
		<dependency>
			<groupId>com.h2database</groupId>
			<artifactId>h2</artifactId>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>com.auth0</groupId>
			<artifactId>java-jwt</artifactId>
			<version>4.4.0</version>
		</dependency>
```
- Após realizar o reload das dependências. 

2. **Configurar Banco de Dados**: Vá para o diretório `src/main/resources` do seu projeto Spring Boot.
 Procure pelo arquivo `application.properties`, abra o arquivo `application.properties` e adicione as configurações do Banco de Dados H2.
- Copie e Cole:
```properties 
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.driver-class-name=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=
```
3. **Criar entidade que representa o usuário**: Crie um pacote chamado `domain`, em seguida dentro do pacote `spring.security.login.auth.api.domain` crie outro pacote e chame-o de `user`. Crie uma classe Java chamada `User` dentro do pacote `spring.security.login.auth.api.domain.user`. Esta classe representará a entidade de usuário em nosso sistema. 
```java
package spring.security.login.auth.api.domain.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String name;

    private String email;

    private String password;
}
```
4. **Crie uma interface chamada `UserRepository`** :Criar um pacote chamado `repositories`, dentro do pacote `spring.security.login.auth.api.repositories` criar a interface chamada `UserRepository`. Esta interface estenderá `JpaRepository` e será responsável por fornecer métodos para realizar operações de persistência relacionadas à entidade `User`.
```java
package spring.security.login.auth.api.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.login.auth.api.domain.user.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmail(String email);
}
```
5. **Crie TokenService**: Crie um pacote chamado `infra`, dentro deste pacote `spring.security.login.auth.api.infra` crie outro pacote chamado `security`. Em seguida, Crie uma classe chamada `TokenService` dentro do pacote `spring.security.login.auth.api.infra.security`. Este serviço será responsável por gerar e validar tokens JWT.
```java
package spring.security.login.auth.api.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import spring.security.login.auth.api.domain.user.User;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    public String generateToken(User user){
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);

            String token = JWT.create()
                    .withIssuer("login-auth-api")
                    .withSubject(user.getEmail())
                    .withExpiresAt(this.generateExpirationDate())
                    .sign(algorithm);
            return token;
        } catch (JWTCreationException exception){
            throw new RuntimeException("Error while generating token");
        }
    }

    public String validateToken(String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("login-auth-api")
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException exception) {
            return null;
        }
    }

    private Instant generateExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
```
6. **Criar SecurityConfig**: Crie uma classe chamada `SecurityConfig` dentro do pacote `spring.security.login.auth.api.infra.security`. Esta classe será responsável por configurar a segurança do aplicativo.
```java 
package spring.security.login.auth.api.infra.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

 @Autowired
 private CustomUserDetailsService userDetailsService;

 @Autowired
 SecurityFilter securityFilter;

 @Bean
 public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
  http
          .csrf(csrf -> csrf.disable())
          .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
          .authorizeHttpRequests(authorize -> authorize
                  .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                  .requestMatchers(HttpMethod.POST, "/auth/register").permitAll()
                  .anyRequest().authenticated()
          )
          .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class);
  return http.build();
 }

 @Bean
 public PasswordEncoder passwordEncoder() {
  return new BCryptPasswordEncoder();
 }

 @Bean
 public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
  return authenticationConfiguration.getAuthenticationManager();
 }
}
```
7. **Criar CustomUserDetailsService**: Crie uma classe chamada `CustomUserDetailsService` dentro do pacote `spring.security.login.auth.api.infra.security`. Este serviço será uma implementação da interface `UserDetailsService` do Spring Security.
```java 
package spring.security.login.auth.api.infra.security;

import spring.security.login.auth.api.domain.user.User;
import spring.security.login.auth.api.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = this.repository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), new ArrayList<>());
    }
}
```

8. **Criar SecurityFilter**: Crie uma classe chamada `SecurityFilter` dentro do pacote `spring.security.login.auth.api.infra.security`. Este filtro será uma subclasse de `OncePerRequestFilter` do Spring e será responsável por realizar o processamento de segurança para cada requisição.
```java 
package spring.security.login.auth.api.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import spring.security.login.auth.api.domain.user.User;
import spring.security.login.auth.api.repositories.UserRepository;

import java.io.IOException;
import java.util.Collections;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    TokenService tokenService;

    @Autowired
    UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var token = this.recoverToken(request);
        var login = tokenService.validateToken(token);

        if(login != null){
            User user = userRepository.findByEmail(login).orElseThrow(() -> new RuntimeException("User Not Found"));
            var authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
            var authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

    private String recoverToken(HttpServletRequest request){
        var authHeader = request.getHeader("Authorization");
        if(authHeader == null) return null;
        return authHeader.replace("Bearer ", "");
    }
}
```
9. **Criar um AuthController**: Crie um novo pacote chamado `controllers`, dentro deste pacote, crie uma classe chamada `AuthController` dentro do pacote `spring.security.login.auth.api.controllers`. Esta classe conterá os endpoints para autenticação e registro de usuários.
```java 
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

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO body){
        User user = this.repository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User not found."));
        if(passwordEncoder.matches(body.password(), user.getPassword())){
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getName(),token ));
        }
        return ResponseEntity.badRequest().build();
    }

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
```
10. **Criar UserController**: Crie uma classe chamada `UserController` dentro do pacote `spring.security.login.auth.api.controllers`. Esta classe conterá o endpoint para obter informações do usuário.
```java 
package spring.security.login.auth.api.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping
    public ResponseEntity<String> getUser(){
        return ResponseEntity.ok("sucesso!");
    }
}
```
11. **Criar DTO's para Request e Response**: 
**A) LoginRequestDTO**: Crie um novo pacote chamado `dto`. Crie uma classe chamada `LoginRequestDTO` dentro do pacote `spring.security.login.auth.api.dto`. Este DTO conterá os campos de e-mail e senha necessários para solicitar a autenticação de um usuário.
```java 
package spring.security.login.auth.api.dto;

public record LoginRequestDTO(String email, String password) {
}
```
**B) RegisterRequestDTO**: Crie uma classe chamada `RegisterRequestDTO` dentro do pacote `spring.security.login.auth.api.dto`. Este DTO conterá os campos de nome, e-mail e senha necessários para solicitar o registro de um novo usuário.
```java
package spring.security.login.auth.api.dto;

public record RegisterRequestDTO(String name, String email, String password) {
}
```
**C) ResponseDTO**: Crie uma classe chamada `ResponseDTO` dentro do pacote `spring.security.login.auth.api.dto`. Este DTO conterá os campos de nome do usuário e token gerado após uma solicitação de autenticação ou registro bem-sucedida.

```java
package spring.security.login.auth.api.dto;

public record ResponseDTO(String name, String token) {
}
```
- A partir deste ponto a aplicação pode ser testada.

# FIM. 


