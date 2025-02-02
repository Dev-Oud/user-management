package Demo.user.management.Dto;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    private String firstName;
    private String secondName;
    private String lastName;
    private String username;
    private String password;
    private String accountNumber;
    private double balance;
}
