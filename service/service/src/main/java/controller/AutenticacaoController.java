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
import service.ServiceAutenticacao;

@RestController
@AllArgsConstructor
@RequestMapping("/auth")
public class AutenticacaoController {

    private final ServiceAutenticacao autenticacao;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request){
        String token = autenticacao.login(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(new AuthResponse(token));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request){
        autenticacao.register(request.getUsername(), request.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).body("Usuário cadastrado com sucesso!");
    }
}