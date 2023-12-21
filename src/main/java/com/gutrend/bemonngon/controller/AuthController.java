package com.gutrend.bemonngon.controller;

import com.gutrend.bemonngon.config.Constant;
import com.gutrend.bemonngon.dto.request.ChangeAvatar;
import com.gutrend.bemonngon.dto.request.SignInForm;
import com.gutrend.bemonngon.dto.request.SignUpForm;
import com.gutrend.bemonngon.dto.request.UpdateUser;
import com.gutrend.bemonngon.dto.response.JwtResponse;
import com.gutrend.bemonngon.dto.response.ResponseMessage;
import com.gutrend.bemonngon.model.user.Role;
import com.gutrend.bemonngon.model.user.RoleName;
import com.gutrend.bemonngon.model.user.User;
import com.gutrend.bemonngon.security.jwt.JwtProvider;
import com.gutrend.bemonngon.security.jwt.JwtTokenFilter;
import com.gutrend.bemonngon.security.userprincal.UserDetailService;
import com.gutrend.bemonngon.security.userprincal.UserPrinciple;
import com.gutrend.bemonngon.service.UserIMPL.RoleServiceIMPL;
import com.gutrend.bemonngon.service.UserIMPL.UserServiceIMPL;
import com.gutrend.bemonngon.util.EmailUtil;
import com.gutrend.bemonngon.util.OtpUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@RequestMapping("/")
@RestController
@CrossOrigin(origins = "*")
public class AuthController {
    @Autowired
    UserServiceIMPL userServiceIMPL;
    @Autowired
    RoleServiceIMPL roleServiceIMPL;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    JwtProvider jwtProvider;
    @Autowired
    JwtTokenFilter jwtTokenFilter;
    @Autowired
    private OtpUtil otpUtil;
    @Autowired
    private EmailUtil emailUtil;
    @Autowired
    private UserDetailService userDetailService;


    @GetMapping("/list-user")
    public ResponseEntity<?> getListUser() {
        return new ResponseEntity<>(userServiceIMPL.findAll(), HttpStatus.OK);
    }

    @GetMapping("/detail-user/{id}")
    public ResponseEntity<?> detailUserById(@PathVariable Long id) {
        Optional<User> user = userServiceIMPL.findByUserId(id);
        if (!user.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage(Constant.ID_DOSE_NOT_EXIST), HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(user, HttpStatus.OK);
    }




    @PostMapping("/signup")
    public ResponseEntity<?> register(@Valid @RequestBody SignUpForm signUpForm) {
        if (userServiceIMPL.existsByUsername(signUpForm.getUsername())) {
            return new ResponseEntity<>(new ResponseMessage(Constant.USERNAME_EXIST), HttpStatus.OK);
        }
        if (userServiceIMPL.existsByEmail(signUpForm.getEmail())) {
            return new ResponseEntity<>(new ResponseMessage(Constant.EMAIL_EXIST), HttpStatus.OK);
        }
        String otp = otpUtil.generateOtp();
        try {
            emailUtil.sendOtpEmail(signUpForm.getEmail(), otp);
        } catch (MessagingException e) {
            throw new RuntimeException("Unable to send otp please try again");
        }
        User user = new User(signUpForm.getName(),
                signUpForm.getUsername(),
                signUpForm.getEmail(),
                passwordEncoder.encode(signUpForm.getPassword())
        );
        user.setOtp(otp);
        user.setOtpGeneratedTime(LocalDateTime.now());

        Set<String> strRoles = signUpForm.getRoles();
        Set<Role> roles = new HashSet<>();
        strRoles.forEach(role -> {
            switch (role) {
                case "admin":
                    Role adminRole = roleServiceIMPL.findByName(RoleName.ADMIN).orElseThrow(
                            () -> new RuntimeException("Role not found")
                    );
                    roles.add(adminRole);
                    break;
                case "pm":
                    Role pmRole = roleServiceIMPL.findByName(RoleName.PM).orElseThrow(() -> new RuntimeException("Role not found"));
                    roles.add(pmRole);
                    break;
                default:
                    Role userRole = roleServiceIMPL.findByName(RoleName.USER).orElseThrow(() -> new RuntimeException("Role not found"));
                    roles.add(userRole);
            }
        });
        user.setRoles(roles);
        userServiceIMPL.save(user);
        return new ResponseEntity<>(new ResponseMessage(Constant.CREATE_SUCCESS), HttpStatus.OK);
    }

    @PutMapping("/verify-account")
    public ResponseEntity<?> verifyAccount(@RequestParam String email,
                                           @RequestParam String otp) {
        User user = userServiceIMPL.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with this email: " + email));
        if (user.getOtp().equals(otp) && Duration.between(user.getOtpGeneratedTime(),
                LocalDateTime.now()).getSeconds() < (1 * 60)) {
            user.setActive(true);
            userServiceIMPL.save(user);
            return new ResponseEntity<>(new ResponseMessage(Constant.OTP_VERIFICATION_SUCCESSFUL), HttpStatus.OK);
        }
        return new ResponseEntity<>(new ResponseMessage(Constant.REGENERATE_OTP), HttpStatus.OK);
    }

    @PutMapping("/regenerate-otp")
    public ResponseEntity<?> regenerateOtp(@RequestParam String email) {
        User user = userServiceIMPL.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with this email: " + email));
        String otp = otpUtil.generateOtp();
        try {
            emailUtil.sendOtpEmail(email, otp);
        } catch (MessagingException e) {
            throw new RuntimeException("Unable to send otp please try again");
        }
        user.setOtp(otp);
        user.setOtpGeneratedTime(LocalDateTime.now());
        userServiceIMPL.save(user);
        return new ResponseEntity<>(new ResponseMessage(Constant.OTP_SENT_SUCCESS), HttpStatus.OK);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> login(@Valid @RequestBody SignInForm signInForm) {
        if (signInForm.getUsername().isEmpty()) {
            return new ResponseEntity<>(new ResponseMessage(Constant.USERNAME_CANNOT_BLANK), HttpStatus.OK);
        }
        if (signInForm.getPassword().isEmpty()) {
            return new ResponseEntity<>(new ResponseMessage(Constant.PASSWORD_CANNOT_BLANK), HttpStatus.OK);
        }
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(signInForm.getUsername(), signInForm.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String token = jwtProvider.createToken(authentication);
            String username = jwtProvider.getUerNameFromToken(token);
            User user = userServiceIMPL.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("user name not found"));
            if (!user.isActive()) {
//                return "your account is not verified";
                return new ResponseEntity<>(new ResponseMessage(Constant.ACCOUNT_N0T_VERIFIED), HttpStatus.OK);
            }
            if (user.getStatus()) {
                return new ResponseEntity<>(new ResponseMessage(Constant.ACCOUNT_BLOCK), HttpStatus.UNAUTHORIZED);
            }
            UserPrinciple userPrinciple = (UserPrinciple) authentication.getPrincipal();
            return ResponseEntity.ok(new JwtResponse(token, userPrinciple.getName(), userPrinciple.getAvatar(), userPrinciple.getAuthorities()));

        } catch (BadCredentialsException e) {
            // Xử lý ngoại lệ khi sai password
            return new ResponseEntity<>(new ResponseMessage(Constant.INVALID_PASSWORD), HttpStatus.UNAUTHORIZED);
        } catch (AuthenticationException e) {
            // Xử lý ngoại lệ khác khi đăng nhập không thành công (có thể là sai username)
            return new ResponseEntity<>(new ResponseMessage(Constant.INVALID_CREDENTIALS), HttpStatus.UNAUTHORIZED);
        }
    }

    @PutMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        Optional<User> userOptional = userServiceIMPL.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            String otp = otpUtil.generateOtp();
            try {
                emailUtil.sendSetPasswordOtpEmail(email, otp);
            } catch (MessagingException e) {
                // Handle specific exception for email sending failure
                return new ResponseEntity<>(new ResponseMessage("Unable to send OTP. Please try again."), HttpStatus.INTERNAL_SERVER_ERROR);
            }

            user.setOtp(otp);
            user.setOtpGeneratedTime(LocalDateTime.now());
            userServiceIMPL.save(user);

            return new ResponseEntity<>(new ResponseMessage("Check your email for the OTP."), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new ResponseMessage(Constant.EMAIL_DOES_NOT_EXIST), HttpStatus.NOT_FOUND);
        }
    }

    @PutMapping("/regenerate-otp-change-password")
    public ResponseEntity<?> regenerateOtpChangePassword(@RequestParam String email) {
        User user = userServiceIMPL.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with this email: " + email));
        String otp = otpUtil.generateOtp();
        try {
            emailUtil.sendSetPasswordOtpEmail(email, otp);
        } catch (MessagingException e) {
            throw new RuntimeException("Unable to send otp please try again");
        }
        user.setOtp(otp);
        user.setOtpGeneratedTime(LocalDateTime.now());
        userServiceIMPL.save(user);
        return new ResponseEntity<>(new ResponseMessage(Constant.OTP_SENT_SUCCESS), HttpStatus.OK);
    }
    @PutMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestParam String email,
            @RequestParam String otp,
            @RequestHeader String newPassword) {

        Optional<User> userOptional = userServiceIMPL.findByEmail(email);

        if (userOptional.isPresent()) {
            User user = userOptional.get();

            if (user.getOtp().equals(otp) && Duration.between(user.getOtpGeneratedTime(),
                    LocalDateTime.now()).getSeconds() < (1 * 60)) {
                // Mã hóa mật khẩu trước khi đặt
                user.setPassword(passwordEncoder.encode(newPassword));
                userServiceIMPL.save(user);
                return new ResponseEntity<>(new ResponseMessage(Constant.PASSWORD_SET_SUCCESSFULY), HttpStatus.OK);
            } else {
                return new ResponseEntity<>(new ResponseMessage(Constant.REGENERATE_OTP), HttpStatus.BAD_REQUEST);
            }
        } else {
            // Người dùng không được tìm thấy
            return new ResponseEntity<>(new ResponseMessage("Không tìm thấy người dùng với địa chỉ email này: " + email), HttpStatus.NOT_FOUND);
        }
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        try {
            String token = jwtTokenFilter.getJwt(request);

            if (token != null && !token.isEmpty()) {
                // Kiểm tra xem token có hết hạn hay không
                if (jwtProvider.isTokenExpired(token)) {
                    // Gửi ResponseMessage khi token đã hết hạn
                    return new ResponseEntity<>(new ResponseMessage(Constant.TOKEN_EXPIRED), HttpStatus.UNAUTHORIZED);
                }
                // Invalidate token
                jwtProvider.invalidateToken(token);
                SecurityContextHolder.getContext().setAuthentication(null);
                return new ResponseEntity<>(new ResponseMessage(Constant.SIGNOUT_SUCCESS), HttpStatus.OK);
            } else {
                // Gửi ResponseMessage khi token không tồn tại
                return new ResponseEntity<>(new ResponseMessage(Constant.TOKEN_NOT_EXIST), HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            // Xử lý ngoại lệ và gửi ResponseMessage khi có lỗi
            return new ResponseEntity<>(new ResponseMessage(Constant.SIGNOUT_FAILURE), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/change-avatar")
    public ResponseEntity<?> changeAvatar(HttpServletRequest request, @Valid @RequestBody ChangeAvatar changeAvatar) {
        String token = jwtTokenFilter.getJwt(request);
        String username = jwtProvider.getUerNameFromToken(token);
        User user = userServiceIMPL.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Username not found"));

        boolean checkNewAvatar = changeAvatar.getAvatar() == null || changeAvatar.getAvatar().trim().equals("");
        boolean checkChangeAvatar = false;

        try {
            URL urlNew = new URL(changeAvatar.getAvatar());
            URL urlOld = new URL(user.getAvatar());
            if (urlNew.equals(urlOld)) {
                checkChangeAvatar = true;
            }
        } catch (MalformedURLException e) {
            return new ResponseEntity<>(new ResponseMessage(Constant.INVALID_URL_FORMAT), HttpStatus.NOT_FOUND);
        }
        if (checkNewAvatar) {
            return new ResponseEntity<>(new ResponseMessage(Constant.UPDATE_FAIL), HttpStatus.OK);
        } else if (checkChangeAvatar) {
            return new ResponseEntity<>(new ResponseMessage(Constant.NO_CHANGE), HttpStatus.OK);
        } else {
            user.setAvatar(changeAvatar.getAvatar());
            userServiceIMPL.save(user);
            return new ResponseEntity<>(new ResponseMessage(Constant.UPDATE_SUCCESS), HttpStatus.OK);
        }
    }

    @PutMapping("/update-user")
    public ResponseEntity<?> updateUser(HttpServletRequest request, @Valid @RequestBody UpdateUser updateUser) {
        String token = jwtTokenFilter.getJwt(request);
        String username = jwtProvider.getUerNameFromToken(token);
        User user = userServiceIMPL.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User name not found"));
        if (user.getStatus()) {
            return new ResponseEntity<>(new ResponseMessage(Constant.ACCESS_IS_DENIED), HttpStatus.OK);
        }
        boolean checkNewAvatar = updateUser.getAvatar() == null || updateUser.getAvatar().trim().equals("");
        boolean checkName = updateUser.getName().equals(user.getName());
        boolean checkPassword = passwordEncoder.matches(updateUser.getPassword(), user.getPassword());
        boolean checkChangeAvatar = false;
        try {
            URL urlNew = new URL(updateUser.getAvatar());
            URL urlOld = new URL(user.getAvatar());
            if (urlNew.equals(urlOld)) {
                checkChangeAvatar = true;
            }
        } catch (MalformedURLException e) {
            return new ResponseEntity<>(new ResponseMessage(Constant.INVALID_URL_FORMAT), HttpStatus.NOT_FOUND);
        }
        if (checkNewAvatar) {
            return new ResponseEntity<>(new ResponseMessage("avatar_failed"), HttpStatus.OK);
        } else if (checkName && checkPassword && checkChangeAvatar) {
            return new ResponseEntity<>(new ResponseMessage(Constant.NO_CHANGE), HttpStatus.OK);
        } else {
            user.setName(updateUser.getName());
            user.setAvatar(updateUser.getAvatar());
            user.setPassword(passwordEncoder.encode(updateUser.getPassword()));
            userServiceIMPL.save(user);
            return new ResponseEntity<>(new ResponseMessage("update_success"), HttpStatus.OK);
        }
    }

    @PutMapping("/change-role/{id}")
    public ResponseEntity<?> changeRoleOfUser(@PathVariable Long id) {
        Optional<User> user = userServiceIMPL.findByUserId(id);
        Set<Role> roles = new HashSet<>();
        String roleMaster = "";
        if (!user.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage(Constant.ID_DOSE_NOT_EXIST), HttpStatus.OK);
        } else {
            User userMaster = userDetailService.getCurrentUser();
            roleMaster = userServiceIMPL.getUserRole(userMaster);
            if (!roleMaster.equals("ADMIN")) {
                return new ResponseEntity<>(new ResponseMessage(Constant.ACCESS_IS_DENIED), HttpStatus.OK);
            } else {
                if (userServiceIMPL.getUserRole(user.get()).equals("ADMIN")) {
                    return new ResponseEntity<>(new ResponseMessage(Constant.ADMIN_ROLES_CANNOT_CHANGE), HttpStatus.OK);
                } else {
                    if (userServiceIMPL.getUserRole(user.get()).equals("USER")) {
                        Role pmRole = roleServiceIMPL.findByName(RoleName.PM).orElseThrow(() -> new RuntimeException("Role not found"));
                        roles.add(pmRole);
                    }
                    if (userServiceIMPL.getUserRole(user.get()).equals("PM")) {
                        Role userRole = roleServiceIMPL.findByName(RoleName.USER).orElseThrow(() -> new RuntimeException("Role not found"));
                        roles.add(userRole);
                    }
                    user.get().setRoles(roles);
                    userServiceIMPL.save(user.get());
                    return new ResponseEntity<>(new ResponseMessage(Constant.UPDATE_SUCCESS), HttpStatus.OK);
                }
            }
        }
    }

    @PutMapping("/block-user/{id}")
    public ResponseEntity<?> blockUser(@PathVariable Long id) {
        Optional<User> user = userServiceIMPL.findByUserId(id);
        String roleMaster = "";
        if (!user.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage(Constant.ID_DOSE_NOT_EXIST), HttpStatus.OK);
        } else {
            User userMaster = userDetailService.getCurrentUser();
            roleMaster = userServiceIMPL.getUserRole(userMaster);
            if (!roleMaster.equals("ADMIN") && !roleMaster.equals("PM")) {
                return new ResponseEntity<>(new ResponseMessage(Constant.ACCESS_IS_DENIED), HttpStatus.OK);
            }
            if (userServiceIMPL.getUserRole(user.get()).equals("ADMIN")) {
                return new ResponseEntity<>(new ResponseMessage(Constant.CANNOT_BLOCK_ADMIN), HttpStatus.OK);
            }
            user.get().setStatus(!user.get().getStatus());
            userServiceIMPL.save(user.get());
            return new ResponseEntity<>(new ResponseMessage(Constant.UPDATE_SUCCESS), HttpStatus.OK);
        }
    }

}
