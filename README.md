# spring-security
Projeto de Spring Security de Programação Orientada a Objetos

# Realizando requisições no Insomnia:

POST http://localhost:8080/auth/register
JSON: 
{
	"name": "Beatriz",
	"email": "teste@gmail.com",
	"password": "123456789"
}

GET http://localhost:8080/user
Enable Bearer + token gerado por auth/register

POST http://localhost:8080/auth/login
JSON:
{
	"email": "teste@gmail.com",
	"password": "123456789"
}