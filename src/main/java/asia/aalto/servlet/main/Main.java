package asia.aalto.servlet.main;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.webapp.WebAppContext;

public class Main {

	private final static int http_port = 8080;
	private final static int https_port = 8089;

	public static void main(String[] args) {

		String webappDirLocation = "src/main/webapp";

		Server server = new Server();

		WebAppContext root = new WebAppContext();
		root.setContextPath("/");
		root.setDescriptor(webappDirLocation + "/WEB-INF/web.xml");
		root.setResourceBase(webappDirLocation);
		root.setParentLoaderPriority(true);
		server.setHandler(root);

		ServerConnector connector = new ServerConnector(server);
		connector.setPort(http_port);

		HttpConfiguration https = new HttpConfiguration();
		https.addCustomizer(new SecureRequestCustomizer());

		SslContextFactory sslContextFactory = new SslContextFactory();
		sslContextFactory.setKeyStorePath("configs/serverStore.jks");  // The keystore includes server certificate and client CA
		sslContextFactory.setKeyStorePassword("password");
		sslContextFactory.setKeyManagerPassword("password");
		sslContextFactory.setNeedClientAuth(true);

		ServerConnector sslConnector = new ServerConnector(server, new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory(https));
		sslConnector.setPort(https_port);

		server.setConnectors(new Connector[] { connector, sslConnector });

		try {
			server.start();
			server.join();
		} catch (Exception e) {	
			e.printStackTrace();
		}

	}

}
