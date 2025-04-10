package es.neesis.security.controller;

import es.neesis.security.model.UserDTO;
import es.neesis.security.entities.UserEntity;
import es.neesis.security.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.ui.Model;

import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    @GetMapping("/usuarios")
    public String getUsuarios(HttpServletRequest request, Model model, Authentication authentication) {
        List<UserEntity> usuarios;

        if (hasRole(authentication, "ADMIN")) {
            usuarios = userRepository.findAll();
        } else if (hasRole(authentication, "GESTION")) {
            usuarios = userRepository.findAll()
                    .stream()
                    .filter(u -> u.getRoles().stream().noneMatch(r -> r.getName().equals("ADMIN")))
                    .toList();
        } else if (hasRole(authentication, "CONSULTA")) {
            String username = authentication.getName();
            usuarios = List.of(userRepository.findByUsername(username));
        } else {
            usuarios = List.of();
        }

        List<UserDTO> usuarioDTOs = usuarios.stream()
                .map(user -> new UserDTO(user.getUsername()))
                .collect(Collectors.toList());

        model.addAttribute("usuarios", usuarioDTOs);
        return "usuarios"; // Thymeleaf: src/main/resources/templates/usuarios.html
    }

    private boolean hasRole(Authentication auth, String roleName) {
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equalsIgnoreCase(roleName));
    }
}

