package Auth.service;


import model.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import repository.UserRepository;
import security.JwtUtil;
import service.ServiceAutenticacao;


import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ServiceAutenticacaoTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private ServiceAutenticacao serviceAutenticacao;

    @Test
    void deveRegistrarUsuarioComSenhaCriptografada() {

        String username = "novo_usuario";
        String password = "123";
        when(passwordEncoder.encode(password)).thenReturn("senha_criptografada");

        serviceAutenticacao.register(username, password);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture()); // Verifica se o método save foi chamado

        User usuarioSalvo = userCaptor.getValue();
        assertThat(usuarioSalvo.getUsername()).isEqualTo(username);
        assertThat(usuarioSalvo.getPassword()).isEqualTo("senha_criptografada"); // Confirma que a senha foi criptografada
    }

    @Test
    void deveFazerLoginComSucesso() {

        String username = "usuario_existente";
        String password = "senha_correta";
        User usuarioDoBanco = new User(1L, username, "senha_criptografada");

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(usuarioDoBanco));
        when(passwordEncoder.matches(password, "senha_criptografada")).thenReturn(true);
        when(jwtUtil.generateToken(username)).thenReturn("token_jwt_valido");

        String token = serviceAutenticacao.login(username, password);

        assertThat(token).isEqualTo("token_jwt_valido");
    }

    @Test
    void deveLancarExcecaoQuandoUsuarioNaoExisteNoLogin() {

        when(userRepository.findByUsername("usuario_inexistente")).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            serviceAutenticacao.login("usuario_inexistente", "qualquer_senha");
        });

        assertThat(exception.getMessage()).isEqualTo("Usuário não encontrado.");
        verify(passwordEncoder, never()).matches(any(), any()); // Garante que a senha nem foi verificada
        verify(jwtUtil, never()).generateToken(any()); // Garante que o token não foi gerado
    }

    @Test
    void deveLancarExcecaoQuandoSenhaEstiverIncorretaNoLogin() {

        String username = "usuario_existente";
        String password = "senha_incorreta";
        User usuarioDoBanco = new User(1L, username, "senha_criptografada");

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(usuarioDoBanco));
        when(passwordEncoder.matches(password, "senha_criptografada")).thenReturn(false);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            serviceAutenticacao.login(username, password);
        });

        assertThat(exception.getMessage()).isEqualTo("Senha incorreta.");
        verify(jwtUtil, never()).generateToken(any()); // Garante que o token não foi gerado
    }
}