package com.gutrend.bemonngon.dto.request;

public class ChangeAvatar {
    private String avatar;

    public ChangeAvatar(String avatar) {
        this.avatar = avatar;
    }

    public ChangeAvatar() {
    }

    public String getAvatar() {
        return avatar;
    }

    public void setAvatar(String avatar) {
        this.avatar = avatar;
    }
}
