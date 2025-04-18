package Demo.user.management.Exceptions;

public class UsernameAlreadyExistsException extends RuntimeException {
    public UsernameAlreadyExistsException(String username) {
        super("Error: Username '" + username + "' already exists.");
    }
}
