package org.example.authentication.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {
    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256); // Dynamically generate a secure key
    private final long expiration = 1000 * 60 * 60; // 1 hour expiration time

    // Generate a JWT token based on username and role provided
    public String generateToken(String username, String role) {
        return Jwts.builder() // Starts building the JWT token
                .setSubject(username) // Sets the owner of the token
                .claim("role", role) // Adds the user's role to the token
                .setIssuedAt(new Date()) // Issue date of the token
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // Expiration of the token
                .signWith(key, SignatureAlgorithm.HS256) // Signs the token using the HS256 algorithm and the secret key
                .compact(); // Converts JWT object to string
    }

    // Decodes the token, extracting the claims
    public Claims extractToken(String token) {
        return Jwts.parser() // Use parserBuilder to decode the token
                .setSigningKey(key) // Set the signing key
                .build() // Build the parser
                .parseClaimsJws(token) // Parse the token and retrieve the claims
                .getBody();
    }

    // Validate the token against user details
    public boolean isValidToken(String token, UserDetails userDetails) {
        try {
            Claims claims = extractToken(token);
            String username = claims.getSubject();
            return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    // Check if the token has expired
    private boolean isTokenExpired(String token) {
        final Date expiration = extractToken(token).getExpiration();
        return expiration.before(new Date());
    }
}
