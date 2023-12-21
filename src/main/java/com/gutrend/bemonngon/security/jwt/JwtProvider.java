package com.gutrend.bemonngon.security.jwt;

import com.gutrend.bemonngon.security.userprincal.UserPrinciple;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

@Component
public class JwtProvider {
    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);
    private String jwtSecret = "sonjapan7@gmail.com";
    private int jwtExpiration = 86400;  // in seconds
    private Set<ExpiredToken> invalidatedTokens = new HashSet<>();

    public String createToken(Authentication authentication) {
        UserPrinciple userPrinciple = (UserPrinciple) authentication.getPrincipal();
        return Jwts.builder().setSubject(userPrinciple.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpiration * 1000))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public boolean validateToken(String token) {
        if (isTokenExpired(token) || isTokenInvalidated(token)) {
            return false; // Token has expired or is invalidated
        }

        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature -> Message: {}", e);
        } catch (MalformedJwtException e) {
            logger.error("Invalid format Token -> Message: {}", e);
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token -> Message: {}", e);
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token -> Message: {}", e);
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty --> Message {}", e);
        }
        return false;
    }

    public String getUerNameFromToken(String token) {
        String userName = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
        return userName;
    }

    public void invalidateToken(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
            invalidatedTokens.add(new ExpiredToken(token, claims.getExpiration()));
        } catch (SignatureException | MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            logger.error("Error parsing token to invalidate: {}", e.getMessage());
        }
        // Clean up expired tokens periodically
        cleanupExpiredTokens();
    }

    public boolean isTokenExpired(String token) {
        Date expiration = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getExpiration();
        return expiration.before(new Date());
    }

    private boolean isTokenInvalidated(String token) {
        return invalidatedTokens.stream().anyMatch(t -> t.getToken().equals(token));
    }

    private void cleanupExpiredTokens() {
        Date now = new Date();
        Iterator<ExpiredToken> iterator = invalidatedTokens.iterator();
        while (iterator.hasNext()) {
            ExpiredToken expiredToken = iterator.next();
            if (expiredToken.getExpiration().before(now) || isTokenExpired(expiredToken.getToken())) {
                iterator.remove();
            }
        }
    }

    private static class ExpiredToken {
        private final String token;
        private final Date expiration;

        public ExpiredToken(String token, Date expiration) {
            this.token = token;
            this.expiration = expiration;
        }

        public String getToken() {
            return token;
        }

        public Date getExpiration() {
            return expiration;
        }
    }
}
