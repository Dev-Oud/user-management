package Demo.user.management.Service;

import Demo.user.management.Dto.UserDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDTO userDTO = userService.getUserByUsername(username);

        if (userDTO == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

        return User.withUsername(userDTO.getUsername())
                .password(userDTO.getPassword()) // Ensure password is already hashed
                .roles("USER") // Assign role
                .build();
    }
}
