package myproject.domain.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.Repository;

public interface ApplicationUserRepository/*<ApplicationUser>*/ extends JpaRepository<ApplicationUser,
        Long> {
    ApplicationUser findUserByName(String username);
}


/*
public interface ApplicationUserRepository extends Repository<ApplicationUser,
        Long> {
    ApplicationUser findUserByName(String username);

    public Object save(Object entity);
}
*/
