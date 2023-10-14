package telran.java48.security.components;

import java.util.Optional;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java48.accounting.dao.UserAccountRepository;
import telran.java48.accounting.model.UserAccount;
import telran.java48.post.dao.PostRepository;
import telran.java48.post.model.Post;

@Component("postSecurity")
@RequiredArgsConstructor
public class PostSecurity {
	 final PostRepository postRepository;
	 final UserAccountRepository userAccountRepository;
	 
	 public boolean isAuthor(String id) {		
			Optional<Post> post = postRepository.findById(id);
	        return post.isPresent() && post.get().getAuthor().equals(SecurityContextHolder.getContext().getAuthentication().getName());
		}
	 
	 public boolean hasRole(String role) {
	        String username = SecurityContextHolder.getContext().getAuthentication().getName();
	        Optional<UserAccount> user = userAccountRepository.findById(username);
	        return user.isPresent() && user.get().getRoles().contains(role.toUpperCase());
	    }	

}
