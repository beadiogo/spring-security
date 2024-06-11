# Spring-security
Projeto de Spring Security de Programação Orientada a Objetos.
O Spring Security é um poderoso framework de segurança para aplicações Java. Ele fornece recursos abrangentes para autenticação, autorização, proteção contra ataques comuns, como CSRF e XSS, e integração com sistemas de autenticação externos, como LDAP e OAuth. 


**Realizando requisições no Insomnia:**

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
