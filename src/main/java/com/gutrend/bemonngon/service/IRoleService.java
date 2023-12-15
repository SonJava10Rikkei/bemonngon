package com.gutrend.bemonngon.service;

import com.gutrend.bemonngon.model.Role;
import com.gutrend.bemonngon.model.RoleName;

import java.util.Optional;

public interface IRoleService {
    Optional<Role> findByName(RoleName name);
}
