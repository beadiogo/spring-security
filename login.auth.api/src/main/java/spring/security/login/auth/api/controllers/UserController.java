package spring.security.login.auth.api.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador para operações relacionadas ao usuário.
 */
@RestController
@RequestMapping("/user")
public class UserController {

    /**
     * Endpoint para obter informações do usuário.
     * @return ResponseEntity contendo uma mensagem de sucesso se a operação for bem-sucedida.
     */
    @GetMapping
    public ResponseEntity<String> getUser(){
        return ResponseEntity.ok("sucesso!");
    }
}
