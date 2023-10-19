package telran.java48.security;

import java.time.LocalDate;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java48.accounting.dao.UserAccountRepository;
import telran.java48.accounting.dto.exceptions.UserNotFoundException;
import telran.java48.accounting.model.UserAccount;
import telran.java48.post.dao.PostRepository;
import telran.java48.post.model.Post;

@Service("customSecurity")
@RequiredArgsConstructor
public class CustomWebSecurity {
	final PostRepository postRepository;
	final UserAccountRepository userAccountRepository;
	
	public boolean checkPostAuthor(String postId, String userName) {
		Post post = postRepository.findById(postId).orElse(null);
		return post != null && userName.equalsIgnoreCase(post.getAuthor());
	}
	
	public boolean checkPasswordExpiration(String userName) {
        UserAccount userAccount = userAccountRepository.findById(userName).orElseThrow(UserNotFoundException::new);
        LocalDate expDate = userAccount.getPasswordExpiryDate();

            if (expDate == null || expDate.isAfter(LocalDate.now())) {
                return true;
            }
        return false;
    }

}
