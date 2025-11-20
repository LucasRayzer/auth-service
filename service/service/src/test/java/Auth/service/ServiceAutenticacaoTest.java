package Auth.service; // Pacote conforme o seu arquivo

import Auth.service.client.UserClient;
import dto.AuthResponse;
import dto.RegisterRequest; // Precisa importar o DTO
import java.util.Date;
import model.User;
import model.TipoUsuario; // Precisa importar o Enum
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
import java.util.UUID;

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

    @Mock
    private UserClient userClient;

    @InjectMocks
    private ServiceAutenticacao serviceAutenticacao;

    @Test
    void deveRegistrarUsuarioComSenhaCriptografada() {

        RegisterRequest request = new RegisterRequest();
        request.setNome("Usuario Teste");
        request.setEmail("teste@email.com");
        request.setSenha("senha123");
        request.setEndereco("Rua Teste, 123");
        request.setTelefone("99999-9999");
        request.setTipo(TipoUsuario.CLIENTE);

        String senhaCriptografada = "senha_criptografada_mock";

        when(passwordEncoder.encode("senha123")).thenReturn(senhaCriptografada);

        serviceAutenticacao.register(request);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User usuarioSalvo = userCaptor.getValue();

        assertThat(usuarioSalvo.getUsername()).isEqualTo("teste@email.com");
        assertThat(usuarioSalvo.getSenha()).isEqualTo(senhaCriptografada);
        assertThat(usuarioSalvo.getTipo()).isEqualTo(TipoUsuario.CLIENTE);

        // Captura o payload enviado para o UserClient (User-Service)
        ArgumentCaptor<UserClient.UserCreateRequest> clientRequestCaptor =
                ArgumentCaptor.forClass(UserClient.UserCreateRequest.class);
        verify(userClient).createUser(clientRequestCaptor.capture());
        UserClient.UserCreateRequest clientPayload = clientRequestCaptor.getValue();

        assertThat(clientPayload.nome).isEqualTo("Usuario Teste");
        assertThat(clientPayload.email).isEqualTo("teste@email.com");
        assertThat(clientPayload.senha).isEqualTo(senhaCriptografada);
        assertThat(clientPayload.tipo).isEqualTo(TipoUsuario.CLIENTE);

        // Verifica se o encoder foi chamado 2 vezes
        verify(passwordEncoder, times(2)).encode("senha123");
    }

    @Test
    void deveFazerLoginComSucesso() {
        UUID id = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        String username = "usuario_existente";
        String password = "senha_correta";
        String mockToken = "token_jwt_valido";
        Date mockExpiration = new Date(System.currentTimeMillis() + 3600000);

        User usuarioDoBanco = new User();
        usuarioDoBanco.setId(id);
        usuarioDoBanco.setUsername(username);
        usuarioDoBanco.setSenha("senha_criptografada");

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(usuarioDoBanco));
        when(passwordEncoder.matches(password, "senha_criptografada")).thenReturn(true);
        when(jwtUtil.generateToken(username)).thenReturn(mockToken);
        when(jwtUtil.extractExpiration(mockToken)).thenReturn(mockExpiration);

        AuthResponse response = serviceAutenticacao.login(username, password);

        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo(mockToken);
        assertThat(response.getExpiration()).isEqualTo(mockExpiration);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User usuarioSalvo = userCaptor.getValue();

        assertThat(usuarioSalvo.getId()).isEqualTo(id);
        assertThat(usuarioSalvo.getToken()).isEqualTo(mockToken);
        assertThat(usuarioSalvo.getTokenExpiration()).isEqualTo(mockExpiration);
    }

    @Test
    void deveLancarExcecaoQuandoUsuarioNaoExisteNoLogin() {

        when(userRepository.findByUsername("usuario_inexistente")).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            serviceAutenticacao.login("usuario_inexistente", "qualquer_senha");
        });

        assertThat(exception.getMessage()).isEqualTo("Usuário não encontrado.");

        verify(passwordEncoder, never()).matches(any(), any());
        verify(jwtUtil, never()).generateToken(any());
    }

    @Test
    void deveLancarExcecaoQuandoSenhaEstiverIncorretaNoLogin() {
        UUID id = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
        String username = "usuario_existente";
        String password = "senha_incorreta";

        User usuarioDoBanco = new User();
        usuarioDoBanco.setId(id);
        usuarioDoBanco.setUsername(username);
        usuarioDoBanco.setSenha("senha_criptografada");

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(usuarioDoBanco));
        when(passwordEncoder.matches(password, "senha_criptografada")).thenReturn(false);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            serviceAutenticacao.login(username, password);
        });

        assertThat(exception.getMessage()).isEqualTo("Senha incorreta.");

        verify(jwtUtil, never()).generateToken(any());
        verify(userRepository, never()).save(any());
    }
}