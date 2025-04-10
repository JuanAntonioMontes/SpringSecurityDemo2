package es.neesis.security.repository;

import es.neesis.security.entities.UserEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long>{
    UserEntity findByUsername(String username);
    List<UserEntity> findAll();

    @Query("SELECT u FROM UserEntity u WHERE NOT EXISTS (SELECT r FROM u.roles r WHERE r.name = 'ADMIN')")
    List<UserEntity> findAllWithoutAdmins();
}
