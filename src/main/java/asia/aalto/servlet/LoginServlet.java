package asia.aalto.servlet;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class LoginServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
	{
		response.setContentType("text/html");
		response.setStatus(HttpServletResponse.SC_OK);
		PrintWriter out = response.getWriter();

		final String userName = request.getParameter("username");
		final String password = request.getParameter("password");

		if (UserStorage.containsUser(userName)) {

			UserObject user = UserStorage.getUser(userName);
			if (user.getPassword().equals(password) && user.getUserName().equals(userName)) {
				HttpSession session = request.getSession();
				session.setAttribute("firstName", user.getFirstName());
				session.setAttribute("lastName", user.getLastName());
				out.println("Welcome, " + user.getFirstName() + " " + user.getLastName());
				RequestDispatcher dispatcher = request.getRequestDispatcher("success.html");
				dispatcher.include(request, response);
			}
			else {
				out.println("Username or Password error");
				RequestDispatcher dispatcher = request.getRequestDispatcher("login.html");
				dispatcher.include(request, response);
			}
		}
		else {
			out.println("You are not a registered user. Please register.");
			RequestDispatcher dispatcher = request.getRequestDispatcher("login.html");
			dispatcher.include(request, response);
		}

		out.close();
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
	{	
		doPost(request, response);
	}
}
