// auth-service
package dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;
import model.TipoUsuario;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class RegisterRequest {
    private String nome;
    private String email;
    private String endereco;
    private String telefone;
    private String senha;
    private TipoUsuario tipo;
}
