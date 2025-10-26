# Título: Adoção de JWT (JSON Web Tokens) para Autenticação Stateless

**Status:** Aceito (Implementado)

## Contexto

Em um ambiente de microserviços, precisamos de um mecanismo de autenticação que seja eficiente, seguro e não dependa de um estado centralizado. Os diversos serviços da aplicação precisam de uma forma padronizada para validar a identidade de um usuário a cada requisição.

A arquitetura (Clean Architecture) beneficia-se de um mecanismo de autenticação que se acopla fracamente aos *use cases* de negócio, tratando a segurança como uma preocupação transversal.

A alternativa principal seria a autenticação baseada em sessão (stateful), que exigiria um armazenamento de sessão compartilhado (como um Redis) e consultas a esse repositório a cada requisição, aumentando a latência e a complexidade da infraestrutura.

## Decisão

Decidimos implementar um sistema de autenticação stateless usando **JSON Web Tokens (JWT)**, integrado com o **Spring Security**.

O fluxo de autenticação funciona da seguinte forma:
1.  **Registro (`/auth/register`):** Um novo usuário é criado e sua senha é armazenada no banco de dados como um hash (usando `BCryptPasswordEncoder`).
2.  **Login (`/auth/login`):** O usuário envia credenciais (`username`, `password`). O `ServiceAutenticacao` valida a senha contra o hash armazenado.
3.  **Geração de Token:** Se as credenciais forem válidas, o `JwtUtil` gera um token JWT (assinado com HS256) que contém o `username` e uma data de expiração.
4.  **Armazenamento e Resposta:** O token gerado e sua data de expiração são salvos na entidade `User` no banco de dados e também retornados ao cliente em um `AuthResponse`.
5.  **Requisições Autenticadas:** Para acessar endpoints protegidos, o cliente deve incluir o token no cabeçalho `Authorization` com o prefixo `Bearer `.
6.  **Validação:** O `JwtFilter` intercepta todas as requisições (exceto `/auth/**`). Ele extrai o token, valida sua assinatura e data de expiração usando o `JwtUtil`.
7.  **Contexto de Segurança:** Se o token for válido, o `JwtFilter` popula o `SecurityContextHolder` do Spring, autenticando o usuário para aquela requisição sem a necessidade de consultar o banco de dados.

## Consequências

O que se torna mais fácil ou mais difícil como resultado dessa mudança?

* **Positivas:**
    * **Stateless:** O servidor de autenticação e os demais microserviços não precisam armazenar o estado da sessão. Cada token JWT é auto-contido. Isso permite uma fácil escalabilidade horizontal.
    * **Performance na Validação:** A validação de um token é computacionalmente muito mais rápida do que uma consulta ao banco de dados a cada requisição.
    * **Desacoplamento:** Qualquer microserviço que tenha acesso à `SECRET_KEY` pode validar um token localmente, reduzindo a dependência direta e a latência de rede com o serviço de autenticação.
    * **Padrão de Mercado:** JWT é um padrão amplamente adotado, facilitando a integração com diversos tipos de clientes (Web, Mobile, etc.).

* **Negativas e Riscos:**
    * **Impossibilidade de Invalidação (Logout):** Sendo stateless, um JWT é válido até sua data de expiração. Esta implementação não possui um mecanismo de "logout" forçado. Se um token for roubado, ele permanecerá válido.
    * **Segurança da Chave Secreta:** A `SECRET_KEY` (injetada de `jwt.secret`) torna-se um ponto crítico de segurança. Se ela vazar, qualquer pessoa poderá forjar tokens válidos.
    * **Tamanho do Token:** Se muitos dados (claims) forem adicionados ao payload do JWT, o cabeçalho HTTP pode ficar grande, aumentando o overhead em cada requisição (atualmente, armazena apenas o *subject*, o que é bom).

* **Implicações (Pontos de Atenção na Implementação Atual):**
    * **Armazenamento Redundante do Token:** O `ServiceAutenticacao` salva o token JWT na tabela `users` a cada login. No entanto, o `JwtFilter` (que protege os endpoints) **não** consulta esse valor; ele apenas valida o token pela sua assinatura.
    * **Impacto da Redundância:** Esta escrita no banco de dados a cada login adiciona latência (I/O) sem um benefício aparente para o *processo de validação* atual.
    * **Oportunidade:** Se o objetivo de salvar o token for permitir um "logout" (invalidando o token no DB) ou garantir "apenas uma sessão ativa" (comparando o token recebido com o salvo), o `JwtFilter` precisará ser modificado para consultar o `UserRepository` e realizar essa verificação extra.