# Título: Adoção de JWT (JSON Web Tokens) para Autenticação Stateless

**Status:** Aceito (Implementado)
## Contexto

Em um ambiente de microserviços, precisamos de um mecanismo de autenticação que seja eficiente, seguro e centralizado. 

A arquitetura (Clean Architecture) beneficia-se de um mecanismo que trata a segurança como uma preocupação transversal, desacoplada dos use cases de negócio.

A arquitetura de API Gateway exige um serviço de identidade dedicado que atue como a "fonte da verdade" para autenticação, emitindo tokens e validando-os sob demanda.

A alternativa principal seria a autenticação baseada em sessão (stateful), que exigiria um armazenamento de sessão compartilhado, aumentando a complexidade.

## Decisão

Decidimos implementar um sistema de autenticação usando **JSON Web Tokens (JWT)**, gerenciado centralmente pelo `autenticacao-service` e integrado com o **API Gateway**.

O fluxo de autenticação funciona da seguinte forma:
1.  **Registro:** Um novo usuário é criado no `autenticacao-service` e sua senha é armazenada como hash (`BCryptPasswordEncoder`).
2.  **Login:** O usuário envia credenciais. O `ServiceAutenticacao` valida a senha contra o hash.
3.  **Geração de Token:** Se as credenciais forem válidas, o `JwtUtil` gera um token JWT (assinado com HS256) contendo o `username` (email) e uma data de expiração.
4.  **Armazenamento e Resposta:** O token gerado e sua data de expiração são salvos na entidade `User` no banco de dados e também retornados ao cliente.
5.  **Requisições Autenticadas:** O cliente envia o JWT no cabeçalho para o **API Gateway**.
6.  **Delegação da Validação:** O API Gateway intercepta a requisição e envia o token para o endpoint `/auth/validate` do `autenticacao-service`.
7.  **Validação Centralizada:** O `AutenticacaoController` recebe a requisição em `/auth/validate`, usa o `JwtUtil` para validar a assinatura e expiração do token e, em seguida, consulta o `UserRepository` para buscar os dados do usuário.
8.  **Resposta ao Gateway:** Se o token for válido, o `/auth/validate` retorna os detalhes do usuário ao Gateway, que então enriquece a requisição original e a encaminha ao microserviço de destino.

## Consequências

* **Positivas:**
  * **Centralização da Lógica:** Toda a lógica de emissão e validação de tokens reside em um único serviço.
  * **Segurança na Borda:** Os microserviços internos não precisam ter acesso à `SECRET_KEY` do JWT. Eles apenas confiam nos cabeçalhos injetados pelo Gateway.
  * **Padrão de Mercado:** JWT é um padrão amplamente adotado, facilitando a integração com diversos tipos de clientes.

* **Negativas e Riscos:**
  * **Impossibilidade de Invalidação:** Sendo stateless, um JWT é válido até sua data de expiração. Se um token for roubado, ele permanecerá válido.
  * **Segurança da Chave Secreta:** A `SECRET_KEY` do `autenticacao-service` é o ponto mais crítico de segurança.
  * **Latência de Rede:** Cada requisição autenticada exige uma chamada de rede extra (Gateway -> Auth-Service).
  * **Dependência Crítica:** O `autenticacao-service` torna-se um *single point of failure* para *todas* as requisições autenticadas do sistema.
