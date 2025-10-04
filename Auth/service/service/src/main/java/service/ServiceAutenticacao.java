package service;

import lombok.AllArgsConstructor;

import model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import repository.UserRepository;
import security.JwtUtil;

@Service
@AllArgsConstructor
public class ServiceAutenticacao {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public String login(String username, String password) {
        var user = userRepository.findByUsername(username).orElseThrow(()->new RuntimeException("Usuário não encontrado."));
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Senha incorreta.");
        }
        return jwtUtil.generateToken(username);
    }

    public void register(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
    }
}