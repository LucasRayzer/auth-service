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


    /**
     * Espera um JSON no corpo da requisição, ex: {"token": "eyJ..."}
     */
    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestBody Map<String, String> request) {
        String token = request.get("token");

        if (token == null || token.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "Token não fornecido."));
        }

        try {
            boolean isValid = jwtUtil.validateToken(token);
            if (isValid) {
                // Se válido, extrai o username e retorna
                String username = jwtUtil.extractUsername(token);
                return ResponseEntity.ok(Map.of("valid", true, "username", username));
            } else {
                // A classe JwtUtil já trata exceções e retorna false, mas por segurança:
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("valid", false, "error", "Token inválido ou expirado."));
            }
        } catch (Exception e) {
            // Captura qualquer outra exceção que possa ocorrer
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("valid", false, "error", e.getMessage()));
        }
    }
}