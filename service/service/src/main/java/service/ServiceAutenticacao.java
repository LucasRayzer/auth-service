package service;

import Auth.service.client.UserClient;
import dto.AuthResponse;
import dto.RegisterRequest;
import lombok.AllArgsConstructor;
import model.TipoUsuario;
import model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import repository.UserRepository;
import security.JwtUtil;

import java.util.Date;
import java.util.Map;

@Service
@AllArgsConstructor
public class ServiceAutenticacao {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final UserClient userClient;

    public AuthResponse login(String username, String senha) {
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado."));

        if (!passwordEncoder.matches(senha, user.getSenha())) {
            throw new RuntimeException("Senha incorreta.");
        }

        String token = jwtUtil.generateToken(username);
        Date expiration = jwtUtil.extractExpiration(token);

        user.setToken(token);
        user.setTokenExpiration(expiration);
        userRepository.save(user);

        return new AuthResponse(token, expiration);
    }

    public void register(RegisterRequest req) {
        // 1) salvar credencial no AUTH (username = email)
        User u = new User();
        u.setUsername(req.getEmail());
        u.setSenha(passwordEncoder.encode(req.getSenha()));
        u.setTipo(req.getTipo());
        userRepository.save(u);

        // 2) criar usuário no USER-SERVICE
        var payload = new UserClient.UserCreateRequest();
        payload.nome = req.getNome();
        payload.email = req.getEmail();
        payload.endereco = req.getEndereco();
        payload.telefone = req.getTelefone();
        payload.senha = passwordEncoder.encode(req.getSenha());
        payload.tipo = (req.getTipo() == null) ? TipoUsuario.CLIENTE : req.getTipo();

        userClient.createUser(payload);
    }
}
