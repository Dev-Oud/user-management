package Demo.user.management.Service;

import Demo.user.management.Repository.UserRepository;
//import Demo.user.management.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository; 
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("🔍 Searching for user with username: " + username); // Debugging log
        return userRepository.findByUsername(username)
                .map(user -> {
                    System.out.println("✅ User found: " + user.getUsername()); // Confirm if user exists
                    return org.springframework.security.core.userdetails.User
                            .withUsername(user.getUsername())
                            .password(user.getPassword())
                            .roles("USER") // Customize roles as needed
                            .build();
                })
                .orElseThrow(() -> {
                   // System.out.println("❌ User not found in the database for username: " + username);
                    return new UsernameNotFoundException("User not found with username: " + username);
                });
    }
}
    
