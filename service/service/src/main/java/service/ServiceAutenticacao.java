package service;

import dto.AuthResponse;
import lombok.AllArgsConstructor;

import model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import repository.UserRepository;
import security.JwtUtil;

import java.util.Date;

@Service
@AllArgsConstructor
public class ServiceAutenticacao {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public AuthResponse login(String username, String password) {
        //Encontra o usuário
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado."));

        //Valida a senha
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Senha incorreta.");
        }

        //Gera o token
        String token = jwtUtil.generateToken(username);

        //Extrai a data de expiração
        Date expiration = jwtUtil.extractExpiration(token);

        //Salvar o token e a expiração no usuário
        user.setToken(token);
        user.setTokenExpiration(expiration);
        userRepository.save(user);

        //Retornar o DTO de resposta
        return new AuthResponse(token, expiration);
    }

    public void register(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
    }
}