package telran.java48.accounting.dto.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
public class IllegalRoleException extends IllegalArgumentException{
	private static final long serialVersionUID = 1L;

}
