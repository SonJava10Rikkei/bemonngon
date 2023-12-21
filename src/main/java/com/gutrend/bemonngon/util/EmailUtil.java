package com.gutrend.bemonngon.util;

import com.gutrend.bemonngon.config.Constant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@Component
public class EmailUtil {

    @Autowired
    private JavaMailSender javaMailSender;

    public void sendOtpEmail(String email, String otp) throws MessagingException {
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, "UTF-8");
        String image = "https://firebasestorage.googleapis.com/v0/b/rn-monngonnoingay.appspot.com/o/Email%2FBestPassword.jpg?alt=media&token=cdf2067a-09e9-41cf-bdcd-e93dcf7379d8";
        String link = Constant.Link;

        mimeMessageHelper.setTo(email);
        mimeMessageHelper.setSubject("Verify OTP");
        mimeMessageHelper.setText(
                String.format("""
                        <div style="text-align: center;">
                           <img style="width: 300px; height: 200px;" src=%s alt="Mô tả">
                          <h1>Bảo mật mã OTP của bạn không chia sẻ với bất kỳ ai.</h1>
                          <h2>Mã OTP Món ngon mỗi ngày của bạn là: </h2>
                          <h3 style="color: red;">%s</h3>
                          <h4 style="color: green;">Mã trên có hiệu lực trong vòng 1 phút</h4>
                          <a href="http://%s/verify-account?email=%s&otp=%s" target="_blank">Click link to verify</a>
                        </div>
                        """, image, otp,link, email, otp),
                true
        );
        javaMailSender.send(mimeMessage);
    }

    public void sendSetPasswordOtpEmail(String email, String otp) throws MessagingException {
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, "UTF-8");
        String image = "https://firebasestorage.googleapis.com/v0/b/rn-monngonnoingay.appspot.com/o/Email%2FBestPassword.jpg?alt=media&token=cdf2067a-09e9-41cf-bdcd-e93dcf7379d8";
        String link = Constant.Link;
        mimeMessageHelper.setTo(email);
        mimeMessageHelper.setSubject("Set Password");
        mimeMessageHelper.setText(
                String.format("""
                        <div style="text-align: center;">
                          <img style="width: 300px; height: 200px;" src=%s alt="Mô tả">
                          <h1>Bảo mật mã OTP của bạn không chia sẻ với bất kỳ ai.</h1>
                          <h2>Mã OTP Món ngon mỗi ngày của bạn là: </h2>
                          <h3 style="color: red;">%s</h3>
                          <h4 style="color: green;">Mã trên có hiệu lực trong vòng 1 phút</h4>
                          <a href="http://%s/change-password?email=%s&otp=%s" target="_blank">Click link to set password</a>
                        </div>
                        """, image, otp,link, email, otp),
                true
        );
        javaMailSender.send(mimeMessage);
    }
}
