package spring.security.login.auth.api.dto;

/**
 * DTO (Data Transfer Object) para resposta de solicitação.
 * Este DTO é usado para encapsular as informações de nome do usuário e o token gerado após uma solicitação de autenticação ou registro bem-sucedida.
 */
public record ResponseDTO(String name, String token) {
}
