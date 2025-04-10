package es.neesis.security.repository;

import es.neesis.security.entities.AuthorizedIp;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuthorizedIpRepository extends CrudRepository<AuthorizedIp, Long> {
    List<AuthorizedIp> findAll();
}