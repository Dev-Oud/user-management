package Demo.user.management.model;

import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "Users_Table")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String firstName;
    private String secondName;
    private String lastName;

    @Column(unique = true, nullable = false)
    private String username;

    private String password;
    private String accountNumber;
    private double balance;

    @PrePersist
    public void prePersist() {
        if (this.accountNumber == null) {
            this.accountNumber = generateAccountNumber();
        }
        this.balance = 0.0; // Initial balance set to 0
    }
    private String generateAccountNumber() {
        long number = 1000000000L + (long) (Math.random() * 9000000000L); // Generates a 10-digit number
        return "" + number;
    }
    
}
