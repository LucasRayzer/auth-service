package controller;

import dto.RegisterRequest;
import lombok.AllArgsConstructor;
import dto.LoginRequest;
import dto.AuthResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import repository.UserRepository;
import security.JwtUtil;
import service.ServiceAutenticacao;

import java.util.List;
import java.util.Map;

@RestController
@AllArgsConstructor
@RequestMapping("/auth")
public class AutenticacaoController {

    private final ServiceAutenticacao autenticacao;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request){
        AuthResponse authResponse = autenticacao.login(request.getUsername(), request.getSenha());
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request){
        autenticacao.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body("Usuário cadastrado com sucesso!");
    }


    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestBody Map<String, String> body,
                                           @RequestHeader(value = "Authorization", required = false) String authorization) {
        String token = body != null ? body.get("token") : null;

        if ((token == null || token.isBlank()) && authorization != null && authorization.toLowerCase().startsWith("bearer ")) {
            token = authorization.substring(7).trim();
        }

        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Missing token"));
        }

        if (!jwtUtil.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid or expired token"));
        }

        String username = jwtUtil.extractUsername(token);
        var userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "User not found"));
        }
        var user = userOpt.get();

        return ResponseEntity.ok(Map.of(
                "userId", user.getId(),
                "username", user.getUsername(),
                "roles", List.of(user.getTipo()), // 👈 envia o tipoUsuario
                "expiresAt", jwtUtil.extractExpiration(token).toInstant().toString()
        ));
    }

}