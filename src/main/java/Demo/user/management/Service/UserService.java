package Demo.user.management.Service;

import Demo.user.management.Dto.UserDTO;
import java.util.List;

public interface UserService {
    List<UserDTO> getAllUsers(); // Change this method to return a list of UserDTO

    UserDTO getUserByUsername(String username);

    UserDTO registerUser(UserDTO userDTO);

    UserDTO depositUserBalance(String username, double amount); // Deposit money

    UserDTO withdrawUserBalance(String username, double amount); // Withdraw money

    void deleteUserAccount(String username); // Delete user account

    void updateUser(String username, UserDTO userDTO);
}
