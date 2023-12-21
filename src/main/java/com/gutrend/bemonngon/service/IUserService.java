package com.gutrend.bemonngon.service;

import com.gutrend.bemonngon.model.user.User;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface IUserService {
    Optional<User> findByEmail(String email); //Tim kiem User co ton tai trong DB khong?
    Optional<User> findByUsername(String name); //Tim kiem User co ton tai trong DB khong?
    Boolean existsByUsername(String username); //username da co trong DB chua, khi tao du lieu
    Boolean existsByEmail(String email); //email da co trong DB chua
    User save(User user);

    String getUserRole(User user);

    Optional<User> findByUserId(Long id);
    List<User> findAll();
}
