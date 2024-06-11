# Spring-security
Este projeto implementa autenticação de usuário utilizando Spring Security, JWT (JSON Web Token) e um banco de dados H2. Ele fornece uma estrutura segura para autenticar usuários com login e senha, gerando tokens JWT para acesso seguro aos recursos protegidos da aplicação.

**Recursos Utilizados**
- Spring Web: Para criação de endpoints REST.
- Spring Security: Para configuração de segurança e autenticação.
- Spring Boot Dev Tools: Facilita o desenvolvimento com reinicialização automática.
- Spring Data JPA: Para interação com o banco de dados.
- H2 Database: Um banco de dados em memória para armazenamento de dados de usuário.
- JWT: Utilizado para gerar tokens de acesso seguro.
- Lombok: Simplifica a escrita de código reduzindo a quantidade de boilerplate.

**Instalação e Configuração**
1. Clone este repositório.
2. Certifique-se de ter o JDK e Maven instalados.
3. Abra o IntelliJ IDEA e importe o projeto.
4. Configure as dependências no arquivo pom.xml se necessário (embora isso geralmente seja feito automaticamente pelo IntelliJ).
5. Execute a aplicação clicando com o botão direito do mouse no arquivo Application.java e selecionando "Run Application".
6. Aguarde até que a aplicação seja iniciada e esteja pronta para uso.
7. Acesse os endpoints fornecidos para autenticação e obtenção do token JWT através do navegador ou de uma ferramenta como o Insomnia.

**Exemplo de uso utilizando o Insomnia:**

- POST http://localhost:8080/auth/register
JSON:   
{  
	"name": "Beatriz",  
	"email": "teste@gmail.com",  
	"password": "123456789"  
}  

- GET http://localhost:8080/user
Enable Bearer + token gerado por auth/register

- POST http://localhost:8080/auth/login
JSON:  
{  
	"email": "teste@gmail.com",  
	"password": "123456789"  
}   

**Alunos:**  
	Beatriz Diogo de Almeida  
 	Joel Rodrigues Alves  
  	Laís de Campos Teixeira   
   	Luísa Lion Perina   
    	Tiago dos Santos Souza   
