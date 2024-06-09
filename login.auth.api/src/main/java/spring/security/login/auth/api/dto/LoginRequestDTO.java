package spring.security.login.auth.api.dto;

/**
 * DTO (Data Transfer Object) para solicitação de login.
 * Este DTO é usado para encapsular as informações de e-mail e senha ao solicitar a autenticação de um usuário.
 */
public record LoginRequestDTO(String email, String password) {
}
