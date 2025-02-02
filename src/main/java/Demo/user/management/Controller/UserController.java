package Demo.user.management.Controller;

import Demo.user.management.Dto.UserDTO;
import Demo.user.management.Service.UserService;
import Demo.user.management.Dto.LoginRequest;
import Demo.user.management.Dto.LoginResponse;
import Demo.user.management.Security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    @GetMapping(path = "/{username}")
    public ResponseEntity<UserDTO> getUserByUsername(@PathVariable String username) {
        return ResponseEntity.ok(userService.getUserByUsername(username));
    }

    @PostMapping(path = "/register")
    public ResponseEntity<UserDTO> registerUser(@RequestBody UserDTO userDTO) {
        return ResponseEntity.ok(userService.registerUser(userDTO));
    }

    @PostMapping(path = "/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()));

            // If authentication is successful, generate a JWT token
            String token = jwtTokenProvider.generateToken(authentication);

            return ResponseEntity.ok(new LoginResponse(token));

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    // Endpoint to deposit money into user's account in all
    @PostMapping(path = "/{username}/deposit")
    public ResponseEntity<String> deposit(@PathVariable String username, @RequestParam double amount) {
        try {
            UserDTO userDTO = userService.getUserByUsername(username);
            userService.depositUserBalance(username, amount);
            return ResponseEntity.ok("Deposit successful. New balance: " + userDTO.getBalance());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error during deposit: " + e.getMessage());
        }
    }

    // Endpoint to withdraw money from user's account in all
    @PostMapping(path = "/{username}/withdraw")
    public ResponseEntity<String> withdraw(@PathVariable String username, @RequestParam double amount) {
        try {
            UserDTO userDTO = userService.getUserByUsername(username);
            userService.withdrawUserBalance(username, amount);
            return ResponseEntity.ok("Withdrawal successful. New balance: " + userDTO.getBalance());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error during withdrawal: " + e.getMessage());
        }
    }

    // Endpoint to delete a user's account in all
    @DeleteMapping(path = "/{username}/delete")
    public ResponseEntity<String> deleteAccount(@PathVariable String username) {
        try {
            userService.deleteUserAccount(username);
            return ResponseEntity.ok("User account deleted successfully.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error during account deletion: " + e.getMessage());
        }
    }
}
