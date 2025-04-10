package es.neesis.security.auth;

import es.neesis.security.service.AuthorizedIpService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Order(0)
public class JwtIpFilter extends OncePerRequestFilter {


    private final AuthorizedIpService authorizedIpService;

    public JwtIpFilter(AuthorizedIpService authorizedIpService) {
        this.authorizedIpService = authorizedIpService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        String uri = request.getRequestURI();
        if (uri.startsWith("/h2-console")) {
            filterChain.doFilter(request, response);
            return;
        }
        String remoteIp = request.getRemoteAddr();
        if (!authorizedIpService.isAuthorized(remoteIp)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("Access denied from IP: " + remoteIp);
            return;
        }

        filterChain.doFilter(request, response);
    }
}
