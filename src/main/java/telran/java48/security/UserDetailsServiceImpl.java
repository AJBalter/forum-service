package telran.java48.security;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java48.accounting.dao.UserAccountRepository;
import telran.java48.accounting.model.UserAccount;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
	
	final UserAccountRepository userAccountRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserAccount userAccount = userAccountRepository.findById(username)
				.orElseThrow(() -> new UsernameNotFoundException(username));
		
		
		List<String> rolesList = userAccount.getRoles()
										.stream()
										.map(r -> "ROLE_" + r.toUpperCase())
										.collect(Collectors.toList());
		
		if(isPasswordExpired(userAccount.getPasswordExpiryDate())) {
			rolesList.add("ROLE_EXPIRED");			
		}
		
		String[] roles = rolesList.stream().toArray(String[]::new);
		
		return new User(username, userAccount.getPassword(), AuthorityUtils.createAuthorityList(roles));
	}
	
	public boolean isPasswordExpired(LocalDate expDate) {
        if (expDate == null || expDate.isAfter(LocalDate.now())) {
                return false;
            }
        return true;
    }

}