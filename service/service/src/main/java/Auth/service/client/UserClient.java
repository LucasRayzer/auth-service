package Auth.service.client;// auth-service


import model.TipoUsuario;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class UserClient {
    private final RestTemplate rt = new RestTemplate();
    private final String baseUrl;

    public UserClient(@Value("${services.user.base-url}") String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public void createUser(UserCreateRequest req) {
        rt.postForEntity(baseUrl + "/usuarios", req, Void.class);
    }

    // payload esperado pelo user-service
    public static class UserCreateRequest {
        public String nome;
        public String email;
        public String endereco;
        public String telefone;
        public String senha;
        public TipoUsuario tipo;
    }
}
