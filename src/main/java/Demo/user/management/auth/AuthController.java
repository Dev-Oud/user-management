package Demo.user.management.auth;

//import Demo.user.management.Dto.UserDTO;
//import Demo.user.management.Service.UserService;
import Demo.user.management.Dto.LoginRequest;
import Demo.user.management.Dto.LoginResponse;
import Demo.user.management.Dto.UserDTO;
import Demo.user.management.Exceptions.UsernameAlreadyExistsException;
import Demo.user.management.Security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
//import Demo.user.management.Exceptions.UsernameAlreadyExistsException;
import Demo.user.management.Service.UserService;

//import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;

    // login
    @PostMapping(path = "/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            String username = loginRequest.getUsername();

            //  /Check if the user is completely new (i.e., has no session)
            if (!jwtTokenProvider.hasActiveSession(username)) {
                System.out.println("🔹 New user detected. Proceeding with normal login.");
                return authenticateAndGenerateToken(loginRequest);
            }

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7).trim();
                String usernameFromToken = jwtTokenProvider.extractUsername(token);

                System.out.println("🔹 Extracted Username from Token: " + usernameFromToken);
                System.out.println("🔹 Checking if token is invalidated or expired...");

                if (jwtTokenProvider.isTokenInvalidated(token) || jwtTokenProvider.isTokenExpired(token)) {
                    System.out.println(" Token is expired/invalid. Allowing login...");
                    return authenticateAndGenerateToken(loginRequest);
                }

                System.out.println(" User is already logged in. Blocking login.");
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User is already logged in.");
            }

            System.out.println("🔹 No token found. Proceeding with normal login.");
            return authenticateAndGenerateToken(loginRequest);

        } catch (BadCredentialsException e) {
            System.out.println(" Invalid credentials.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
        }
    }

    //  Helper method: Clears old sessions and generates a new token
    private ResponseEntity<?> authenticateAndGenerateToken(LoginRequest loginRequest) {
        //  Forcefully remove old sessions to avoid duplicate logins
        jwtTokenProvider.forceRemoveUser(loginRequest.getUsername());

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()));

        //  Generate a new token
        String newToken = jwtTokenProvider.generateToken(authentication);
        System.out.println(" User authenticated successfully! New token generated.");

        return ResponseEntity.ok(new LoginResponse(newToken));
    }

    // logout

    @PostMapping(path = "/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("No valid token provided");
        }

        String token = authHeader.substring(7).trim();
        String username = jwtTokenProvider.extractUsername(token);

        if (username == null) {
            return ResponseEntity.badRequest().body("Invalid token");
        }

        // Invalidate token and remove user from active sessions
        jwtTokenProvider.invalidateToken(token);
        jwtTokenProvider.removeActiveUser(username);

        // Double-check user removal
        if (jwtTokenProvider.hasActiveSession(username)) {
            System.out.println(" User still appears active. Forcefully removing...");
            jwtTokenProvider.forceRemoveUser(username);
        }

        System.out.println(" User logged out successfully: " + username);
        return ResponseEntity.ok("Logged out successfully.");
    }

    @PostMapping(path = "/register")
    public ResponseEntity<Object> registerUser(@RequestBody UserDTO userDTO) {
        try {
            // Attempt to register the user
            UserDTO registeredUser = userService.registerUser(userDTO);
            return ResponseEntity.status(HttpStatus.CREATED).body(registeredUser);
        } catch (UsernameAlreadyExistsException e) {
            // If the username already exists, return a BAD_REQUEST response with an error
            // message
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error: Username '" + userDTO.getUsername() + "' already exists.");
        }
    }
}