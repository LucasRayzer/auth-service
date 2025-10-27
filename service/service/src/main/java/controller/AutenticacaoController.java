package controller;

import dto.RegisterRequest;
import lombok.AllArgsConstructor;
import dto.LoginRequest;
import dto.AuthResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import security.JwtUtil;
import service.ServiceAutenticacao;

import java.util.Map;

@RestController
@AllArgsConstructor
@RequestMapping("/auth")
public class AutenticacaoController {

    private final ServiceAutenticacao autenticacao;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request){
        AuthResponse authResponse = autenticacao.login(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(authResponse);
    }
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request){
        autenticacao.register(request.getUsername(), request.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).body("Usuário cadastrado com sucesso!");
    }


    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestBody Map<String, String> body,
                                           @org.springframework.web.bind.annotation.RequestHeader(value = "Authorization", required = false) String authorization) {
        // 1) tenta pegar do body
        String token = body != null ? body.get("token") : null;

        // 2) opcional: fallback para Authorization header (retrocompatível)
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

        var roles = java.util.List.of("USER"); // ajuste se tiver papéis
        var exp = jwtUtil.extractExpiration(token); // se teu JwtUtil expõe isso; senão, remove o expiresAt abaixo

        return ResponseEntity.ok(Map.of(
                "userId", user.getId(),          // Long ou UUID conforme teu modelo
                "username", user.getUsername(),
                "roles", roles,
                "expiresAt", exp != null ? exp.toInstant().toString() : null
        ));
    }

}