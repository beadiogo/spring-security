package spring.security.login.auth.api.dto;

/**
 * DTO (Data Transfer Object) para solicitação de registro.
 * Este DTO é usado para encapsular as informações de nome, e-mail e senha ao solicitar o registro de um novo usuário.
 */
public record RegisterRequestDTO(String name, String email, String password) {
}