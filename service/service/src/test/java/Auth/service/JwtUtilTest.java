package Auth.service;


import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import security.JwtUtil;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtUtilTest {

    private JwtUtil jwtUtil;

    @BeforeEach
        // roda antes de cada teste
    void setUp() {
        // para teste segredo e tempo de expiração fixos
        String segredo = "segredoSuperSecretoParaTestesNaoUseEmProducaoCompridoOSuficiente";
        long expiracao = 3600000;
        jwtUtil = new JwtUtil(segredo, expiracao);
    }

    @Test
    void deveGerarTokenEExtrairUsernameComSucesso() {
        String username = "usuario_teste";

        String token = jwtUtil.generateToken(username);
        String usernameExtraido = jwtUtil.extractUsername(token);

        assertThat(token).isNotNull();
        assertThat(usernameExtraido).isEqualTo(username);
    }

    @Test
    void deveValidarTokenGeradoComSucesso() {

        String token = jwtUtil.generateToken("outro_usuario");

        boolean ehValido = jwtUtil.validateToken(token);

        assertTrue(ehValido);
    }

    @Test
    void deveLancarExcecaoParaTokenExpirado() throws InterruptedException {
        // cria um JwtUtil com expiração de apenas 1 mss
        JwtUtil jwtUtilExpirado = new JwtUtil("chave-secreta-para-teste-de-expiracao-com-tamanho-suficiente", 1);
        String token = jwtUtilExpirado.generateToken("usuario_expirado");

        Thread.sleep(10); // Espera 10ms para garantir que o token expirou

        assertThrows(ExpiredJwtException.class, () -> {
            jwtUtilExpirado.extractUsername(token); // Tenta extrair o username de um token expirado
        });
    }
}