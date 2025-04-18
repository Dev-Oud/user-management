package Demo.user.management.transactions;

import Demo.user.management.Dto.UserDTO;
import Demo.user.management.Service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/transaction")
@RequiredArgsConstructor
public class TransactionController {
    private final UserService userService;

    // Deposit

    @PostMapping("/deposit/{username}")
    public ResponseEntity<String> deposit(@PathVariable String username, @RequestParam double amount) {
        try {
            // Deposit and get the updated user
            UserDTO updatedUser = userService.depositUserBalance(username, amount);

            // Return the updated balance
            return ResponseEntity.ok("Deposit successful. New balance: " + updatedUser.getBalance());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error during deposit: " + e.getMessage());
        }
    }

    //

    @PostMapping("/withdraw/{username}")
    public ResponseEntity<String> withdraw(@PathVariable String username, @RequestParam double amount) {
        try {

            UserDTO updatedUser = userService.withdrawUserBalance(username, amount);

            return ResponseEntity.ok("Withdrawal successful. New balance: " + updatedUser.getBalance());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error during withdrawal: " + e.getMessage());
        }
    }

    // balance check

    @GetMapping("/balance/{username}")
    public ResponseEntity<String> checkBalance(@PathVariable String username) {
        try {
            UserDTO userDTO = userService.getUserByUsername(username);
            return ResponseEntity.ok("Current balance: " + userDTO.getBalance());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error fetching balance: " + e.getMessage());
        }
    }

}
