package Demo.user.management.Service;

import Demo.user.management.Dto.UserDTO;
import Demo.user.management.Exceptions.UsernameAlreadyExistsException;
import Demo.user.management.model.User;
import jakarta.transaction.Transactional;
import Demo.user.management.Repository.UserRepository;
import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public List<UserDTO> getAllUsers() {
        List<User> users = userRepository.findAll(); // Fetch all users from the repository
        return users.stream()
                .map(user -> modelMapper.map(user, UserDTO.class)) // Map User to UserDTO
                .collect(Collectors.toList()); // Return as a list of UserDTO
    }

    @Override
    public UserDTO getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    public UserDTO registerUser(UserDTO userDTO) {
        // Check if username already exists
        if (userRepository.existsByUsername(userDTO.getUsername())) {
            throw new UsernameAlreadyExistsException(userDTO.getUsername());
        }

        // Proceed with user registration
        User user = modelMapper.map(userDTO, User.class);
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        user.setAccountNumber(generateAccountNumber());
        user.setBalance(0.0);

        userRepository.save(user);
        return modelMapper.map(user, UserDTO.class);
    }

    private String generateAccountNumber() {
        long number = 1000000000L + (long) (Math.random() * 9000000000L);
        return "" + number;
    }

    @Transactional
    @Override
    public UserDTO depositUserBalance(String username, double amount) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (amount <= 0) {
            throw new IllegalArgumentException("Amount must be greater than zero.");
        }

        user.setBalance(user.getBalance() + amount);
        userRepository.saveAndFlush(user);

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

    public boolean validateUserLogin(String username, String rawPassword) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return passwordEncoder.matches(rawPassword, user.getPassword());
    }

    @Override
    public void updateUser(String username, UserDTO userDTO) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Update user details
        if (userDTO.getFirstName() != null)
            user.setFirstName(userDTO.getFirstName());
        if (userDTO.getLastName() != null)
            user.setLastName(userDTO.getLastName());
        if (userDTO.getUsername() != null)
            user.setUsername(userDTO.getUsername());

        // Handle password update securely
        if (userDTO.getPassword() != null && !userDTO.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        }

        userRepository.save(user);
    }
}
