package es.neesis.security.service;

import es.neesis.security.repository.AuthorizedIpRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthorizedIpService {

    private final AuthorizedIpRepository ipRepository;
    private Set<String> authorizedIps = new HashSet<>();

    public AuthorizedIpService(AuthorizedIpRepository ipRepository) {
        this.ipRepository = ipRepository;
    }

    @PostConstruct
    public void loadIps() {
        authorizedIps = new HashSet<>();
        ipRepository.findAll().forEach(ip -> authorizedIps.add(ip.getIpAddress()));
    }

    public boolean isAuthorized(String ip) {
        return authorizedIps.contains(ip);
    }
}