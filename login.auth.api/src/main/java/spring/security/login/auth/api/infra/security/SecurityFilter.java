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

/**
 * Filtro de segurança para validar e processar tokens de autenticação.
 */
@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    TokenService tokenService;

    @Autowired
    UserRepository userRepository;

    /**
     * Método para realizar o processamento do filtro de segurança para cada requisição.
     * @param request O objeto HttpServletRequest da requisição.
     * @param response O objeto HttpServletResponse da resposta.
     * @param filterChain O objeto FilterChain para encadear filtros.
     * @throws ServletException Se ocorrer uma exceção relacionada ao servlet durante o processamento da requisição.
     * @throws IOException Se ocorrer uma exceção de entrada/saída durante o processamento da requisição.
     */
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

    /**
     * Método para recuperar o token de autenticação do cabeçalho da requisição.
     * @param request O objeto HttpServletRequest da requisição.
     * @return O token de autenticação recuperado do cabeçalho da requisição, ou null se não estiver presente.
     */
    private String recoverToken(HttpServletRequest request){
        var authHeader = request.getHeader("Authorization");
        if(authHeader == null) return null;
        return authHeader.replace("Bearer ", "");
    }
}
