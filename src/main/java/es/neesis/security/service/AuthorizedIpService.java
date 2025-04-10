package es.neesis.security.service;

import es.neesis.security.repository.AuthorizedIpRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthorizedIpService {

    private final AuthorizedIpRepository ipRepository;

    public AuthorizedIpService(AuthorizedIpRepository ipRepository) {
        this.ipRepository = ipRepository;
    }

    public boolean isAuthorized(String ip) {
        return ipRepository.existsByIpAddress(ip);
    }
}