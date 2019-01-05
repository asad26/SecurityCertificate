package asia.aalto.servlet;

import java.io.Serializable;

public class UserObject implements Serializable {

	private static final long serialVersionUID = 1L;
	private String userName;
	private String email;
	private String firstName;
	private String lastName;
	private String password;

	public UserObject(String fn, String ln, String uname, String email, String pass) {
		this.firstName = fn;
		this.lastName = ln;
		this.userName = uname;
		this.email = email;
		this.password = pass;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String uname) {
		this.userName = uname;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getFirstName() {
		return firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public String getPassword() {
		return password;
	}
}
