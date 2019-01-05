/*
 * Created by Asad Javed on 20/05/2018
 * Aalto University project
 *
 * Last modified 20/05/2019
 */

package asia.aalto.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RegisterServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private long expiryTime;

	private Map<String, UserObject> keyMap = new HashMap<String, UserObject>(); // Temporary user storage corresponding to userID

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
	{
		response.setContentType("text/html");
		response.setStatus(HttpServletResponse.SC_OK);
		PrintWriter out = response.getWriter();

		Properties properties = new Properties();
		properties.put("mail.smtp.auth", "true");
		properties.put("mail.smtp.starttls.enable", "true");
		properties.put("mail.smtp.host", "smtp.gmail.com");
		properties.put("mail.smtp.port", "587");

		final String fromEmail = "";
		final String fromPassword = "";

		final String firstName = request.getParameter("firstname");
		final String lastName = request.getParameter("lastname");
		final String userName = request.getParameter("username");
		final String toEmail = request.getParameter("emailaddress");
		final String toPassword = request.getParameter("password");

		if (!(UserStorage.containsUser(userName))) {  

			Session session = Session.getDefaultInstance(properties,
					new javax.mail.Authenticator() {
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(fromEmail, fromPassword);
				}
			});

			UUID uniqueKey = UUID.randomUUID();
			final String userId = uniqueKey + String.valueOf(userName.hashCode());

			UserObject user = new UserObject(firstName, lastName, userName, toEmail, toPassword);

			keyMap.put(userId, user);

			String content = "Hello, "
					+ "\n\n"
					+ "Please click on the below link to activate/confirm your account."  
					+ "\n\n"
					+ "Please confirm: http://localhost:8080/RegisterServlet/confirm?uid=" + userId 
					+ "\n\n"
					+ "Thank you.";

			String subject = "Please Confirm Account";

			long startTime = System.currentTimeMillis();

			expiryTime = startTime + 3 * 60 * 1000;

			try {
				MimeMessage message = new MimeMessage(session);
				message.setFrom(new InternetAddress(fromEmail));
				message.addRecipient(Message.RecipientType.TO, new InternetAddress(toEmail)); 
				message.setSubject(subject);
				message.setText(content);
				Transport.send(message);
				System.out.println("Sent message successfully...");
				response.sendRedirect("confirm.html");
			} catch (MessagingException e) {
				e.printStackTrace();
			}
		}
		else {
			out.println("You are already registered with username " + userName);
			RequestDispatcher dispatcher = request.getRequestDispatcher("register.html");
			dispatcher.include(request, response); 
		}

		out.close();
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
	{
		response.setContentType("text/html");
		response.setStatus(HttpServletResponse.SC_OK);
		PrintWriter out = response.getWriter();

		final String urlLogin = "http://localhost:8080/login.html";
		final String urlRegister = "http://localhost:8080/register.html";

		long startTime = System.currentTimeMillis();

		if (startTime < expiryTime) {

			final String userId = request.getParameter("uid");

			UserObject user = keyMap.get(userId);

			UserStorage.storeUser(user.getUserName(), user);

			out.println
			( "<html>"
					+ "<head>"
					+ "<title>Registration successful</title>"
					+ "</head>"
					+ "<body>"
					+ "<h3>Your account has been activated. Please login here <a href=" + urlLogin + ">Go to Login</a></h3>"
					+ "</body>"
					+ "</html>"
					);
		}
		else {
			out.println
			( "<html>"
					+ "<head>"
					+ "<title>Link Expired</title>"
					+ "</head>"
					+ "<body>"
					+ "<h3>The activation link has been expired. Please register again.</h3> "
					+ "<br> <br>" 
					+ "<h3><a href=" + urlRegister + ">Register Here</a></h3>"
					+ "</body>"
					+ "</html>"
					);
		}

		out.close();
	}
}
