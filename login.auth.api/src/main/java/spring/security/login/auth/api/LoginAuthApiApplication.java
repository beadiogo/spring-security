package spring.security.login.auth.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Classe principal que inicia a aplicação Spring Boot.
 */
@SpringBootApplication
public class LoginAuthApiApplication {

	/**
	 * Método principal que inicia a aplicação Spring Boot.
	 * @param args Argumentos de linha de comando passados para a aplicação (não utilizado neste caso).
	 */
	public static void main(String[] args) {
		SpringApplication.run(LoginAuthApiApplication.class, args);
	}
}
