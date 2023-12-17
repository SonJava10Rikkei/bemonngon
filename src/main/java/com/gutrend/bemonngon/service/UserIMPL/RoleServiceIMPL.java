package com.gutrend.bemonngon.service.UserIMPL;

import com.gutrend.bemonngon.model.user.Role;
import com.gutrend.bemonngon.model.user.RoleName;
import com.gutrend.bemonngon.repository.IRoleRepository;
import com.gutrend.bemonngon.service.IRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class RoleServiceIMPL implements IRoleService {
    @Autowired
    IRoleRepository roleRepository;
    @Override
    public Optional<Role> findByName(RoleName name) {
        return roleRepository.findByName(name);
    }
}
