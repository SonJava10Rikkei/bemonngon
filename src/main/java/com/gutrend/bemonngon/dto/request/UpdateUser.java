package com.gutrend.bemonngon.dto.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUser {
    private String name;
    private String avatar;
    private String password;
}
