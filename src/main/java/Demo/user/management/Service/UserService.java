package Demo.user.management.Service;

import Demo.user.management.Dto.UserDTO;

public interface UserService {
    UserDTO getUserByUsername(String username);
    UserDTO registerUser(UserDTO userDTO);
    UserDTO depositUserBalance(String username, double amount); // Deposit money
    UserDTO withdrawUserBalance(String username, double amount); // Withdraw money
    void deleteUserAccount(String username); // Delete user account
}


