package com.gutrend.bemonngon.service.impl;

import com.gutrend.bemonngon.model.Role;
import com.gutrend.bemonngon.model.User;
import com.gutrend.bemonngon.repository.IUserRepository;
import com.gutrend.bemonngon.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements IUserService {
    @Autowired
    IUserRepository userRepository;
    @Override
    public Optional<User> findByUsername(String name) {
        return userRepository.findByUsername(name);
    }

    @Override
    public Boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    @Override
    public Boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public User save(User user) {
        return userRepository.save(user);
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
        return userRepository.findById(id);
    }

    @Override
    public List<User> findAll() {
        return userRepository.findAll();
    }
}
