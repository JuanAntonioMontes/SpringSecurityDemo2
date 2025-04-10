
package es.neesis.security.controller;

import es.neesis.security.auth.JwtUtil;
import es.neesis.security.model.AuthRequestDTO;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

@Controller
@RequestMapping("/api")
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @RequestMapping(value = "/login", method = RequestMethod.POST,
            consumes = "application/x-www-form-urlencoded")
    public RedirectView login(AuthRequestDTO request, HttpServletRequest httpRequest, HttpServletResponse response) {
        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        if(auth.isAuthenticated()){
            String ip = httpRequest.getRemoteAddr();
            String location = "Desconocida";
            String token = jwtUtil.generateToken(request.getUsername(), ip, location);
            RedirectView redirectView;
            if(auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equalsIgnoreCase("ADMIN")))
                redirectView = new RedirectView("/private/helloAdmin");
            else
                redirectView = new RedirectView("/private/hello");

            Cookie jwtCookie = new Cookie("jwt", token);
            jwtCookie.setHttpOnly(true);
            jwtCookie.setSecure(false); // Únicamente se pondría a true si las peticiones fuesen HTTPS
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge(24 * 60 * 60); // Validez de un día
            response.addCookie(jwtCookie);
            return redirectView;
        }
        return new RedirectView("/login");
    }

}
