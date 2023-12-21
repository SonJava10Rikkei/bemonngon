package com.gutrend.bemonngon.service.UserIMPL;

import com.gutrend.bemonngon.model.user.Role;
import com.gutrend.bemonngon.model.user.User;
import com.gutrend.bemonngon.repository.IUserRepository;
import com.gutrend.bemonngon.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserServiceIMPL implements IUserService {
    @Autowired
    IUserRepository iUserRepository;

    @Override
    public Optional<User> findByEmail(String email) {
        return iUserRepository.findByEmail(email);
    }

    @Override
    public Optional<User> findByUsername(String name) {
        return iUserRepository.findByUsername(name);
    }

    @Override
    public Boolean existsByUsername(String username) {
        return iUserRepository.existsByUsername(username);
    }

    @Override
    public Boolean existsByEmail(String email) {
        return iUserRepository.existsByEmail(email);
    }

    @Override
    public User save(User user) {
        return iUserRepository.save(user);
    }

    @Override
    public String getUserRole(User user) {
        String strRole = "USER";
        List<Role> roleList = new ArrayList<>();
        user.getRoles().forEach(role -> {
            roleList.add(role);
        });
        for (int i = 0; i < roleList.size(); i++) {
            if (roleList.get(i).getName().name().equals("ADMIN")){
                strRole= "ADMIN";
                return strRole;
            }
            if (roleList.get(i).getName().name().equals("PM")){
                strRole="PM";
            }
        }
        return strRole;
    }

    @Override
    public Optional<User> findByUserId(Long id) {
        return iUserRepository.findById(id);
    }

    @Override
    public List<User> findAll() {
        return iUserRepository.findAll();
    }

}
