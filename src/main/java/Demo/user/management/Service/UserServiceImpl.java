package Demo.user.management.Service;

import Demo.user.management.Dto.UserDTO;
import Demo.user.management.model.User;
import Demo.user.management.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; // Import BCryptPasswordEncoder
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper; // If using ModelMapper for mapping DTOs
    private final BCryptPasswordEncoder passwordEncoder; // Inject BCryptPasswordEncoder

    @Override
    public UserDTO getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    public UserDTO registerUser(UserDTO userDTO) {
        User user = modelMapper.map(userDTO, User.class);
        
        // Encode the password before saving
        String encodedPassword = passwordEncoder.encode(userDTO.getPassword());
        user.setPassword(encodedPassword); // Set the encoded password
        
        user.setAccountNumber(generateAccountNumber());
        user.setBalance(0.0);

        userRepository.save(user);
        return modelMapper.map(user, UserDTO.class);
    }

    private String generateAccountNumber() {
        long number = 1000000000L + (long) (Math.random() * 9000000000L); // Ensures a 10-digit number
        return "" + number;
    }

    @Override
    public UserDTO depositUserBalance(String username, double amount) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (amount <= 0) {
            throw new IllegalArgumentException("Amount must be greater than zero.");
        }

        user.setBalance(user.getBalance() + amount);
        userRepository.save(user);

        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    public UserDTO withdrawUserBalance(String username, double amount) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (amount <= 0) {
            throw new IllegalArgumentException("Amount must be greater than zero.");
        }

        if (user.getBalance() < amount) {
            throw new IllegalArgumentException("Insufficient balance.");
        }

        user.setBalance(user.getBalance() - amount);
        userRepository.save(user);

        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    public void deleteUserAccount(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        userRepository.delete(user);
    }

    // Additional method for login validation
    public boolean validateUserLogin(String username, String rawPassword) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Compare the raw password with the encoded password stored in the database
        return passwordEncoder.matches(rawPassword, user.getPassword());
    }
}
