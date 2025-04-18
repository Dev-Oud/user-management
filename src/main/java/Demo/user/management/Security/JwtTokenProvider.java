package Demo.user.management.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

@Component
public class JwtTokenProvider {

    private SecretKey secretKey;
    private static final long JWT_EXPIRATION = 86400000; // 24 hours

    private final Set<String> invalidatedTokens = ConcurrentHashMap.newKeySet();
    private final Map<String, String> activeUserTokens = new ConcurrentHashMap<>();

    @Value("${jwt.secret}")
    private String rawSecret;

    @PostConstruct
    public void init() {
        rawSecret = rawSecret.trim();
        if (rawSecret.length() < 32) {
            throw new IllegalArgumentException("JWT Secret Key must be at least 32 characters long!");
        }
        this.secretKey = Keys.hmacShaKeyFor(rawSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(Authentication authentication) {
        String username = ((UserDetails) authentication.getPrincipal()).getUsername();
    
        // DEBUG: Print currently active tokens
        System.out.println(" Checking active sessions for user: " + username);
        System.out.println(" Active Users: " + activeUserTokens);
    
        // Check if user already has a valid token
        if (activeUserTokens.containsKey(username)) {
            String existingToken = activeUserTokens.get(username);
    
            // Verify if the token is actually valid
            if (existingToken != null && !isTokenExpired(existingToken) && !isTokenInvalidated(existingToken)) {
                System.out.println(" User already logged in! Blocking new token generation.");
                return existingToken; // Return the existing valid token
            }
    
            // If the existing token is expired or invalid, remove it
            activeUserTokens.remove(username);
            System.out.println("🔄 Expired/invalid token removed. Generating a new one...");
        }
    
        // Generate a new token
        String newToken = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPIRATION))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    
        // ✅ Store the new token in activeUserTokens
        activeUserTokens.put(username, newToken);
    
        System.out.println("🚀 New token generated and stored for user: " + username);
        return newToken;
    }
    

    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (Exception e) {
            return null;
        }
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return token != null
                && username != null
                && username.equals(userDetails.getUsername())
                && !isTokenExpired(token)
                && !isTokenInvalidated(token);
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claimsResolver.apply(claims);
    }

    public void invalidateToken(String token) {
        if (token == null) return;
        
        invalidatedTokens.add(token);

        // Extract username from token
        String username = extractUsername(token);
        if (username != null) {
            activeUserTokens.remove(username);
            System.out.println(" Token invalidated and user removed from active session: " + username);
        }
    }

    public boolean isTokenInvalidated(String token) {
        return invalidatedTokens.contains(token) || isTokenExpired(token);
    }

    public void removeActiveUser(String username) {
        if (username != null) {
            activeUserTokens.remove(username);
            System.out.println(" User removed from active session: " + username);
        }
    }
    
    public boolean hasActiveSession(String username) {
        return activeUserTokens.containsKey(username);
    }
    
    public void forceRemoveUser(String username) {
        activeUserTokens.remove(username);
    }
}
