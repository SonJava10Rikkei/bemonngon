package com.gutrend.bemonngon.service;

import com.gutrend.bemonngon.model.user.Role;
import com.gutrend.bemonngon.model.user.RoleName;

import java.util.Optional;

public interface IRoleService {
    Optional<Role> findByName(RoleName name);
}
