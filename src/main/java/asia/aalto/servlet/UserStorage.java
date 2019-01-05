package asia.aalto.servlet;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class UserStorage implements Serializable {

	private static final long serialVersionUID = 1L;
	private static Map<String, UserObject>  map = new HashMap<String, UserObject>();

	public static void storeUser(String username, UserObject user) {
		map.put(username, user);
	}

	public static void storeUser(String username, String fn, String ln, String uname, String email, String pass) {
		UserObject user = new UserObject(fn, ln, uname, email, pass);
		map.put(username, user);
	}

	public static UserObject getUser(String username) {
		UserObject user = map.get(username);
		return user;	
	}

	public static Boolean containsUser(String username) {
		return map.containsKey(username);
	}

}
