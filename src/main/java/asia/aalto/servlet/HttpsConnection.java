package asia.aalto.servlet;

import java.io.FileInputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class HttpsConnection {

	public void acceptCertificate()
	{
		try {
			Security.insertProviderAt(new BouncyCastleProvider(), 1);

			final char[] passwd = "password".toCharArray();  // Password for key store

			KeyStore clientStore = KeyStore.getInstance("PKCS12", "BC");
			clientStore.load(new FileInputStream("client.p12"), passwd);

			KeyManagerFactory kmFactory = KeyManagerFactory.getInstance("BC");
			kmFactory.init(clientStore, passwd);
			KeyManager[] keyManager = kmFactory.getKeyManagers();

			//KeyStore trustStore = KeyStore.getInstance("JKS");
			//trustStore.load(new FileInputStream("C:/Program Files/Java/jdk1.8.0_101/jre/lib/security/cacerts"), "changeit".toCharArray());
			//TrustManagerFactory tmFactory = TrustManagerFactory.getInstance("BC");
			//tmFactory.init(trustStore);
			//TrustManager[] trustManager = tmFactory.getTrustManagers();

			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(keyManager, null, new SecureRandom());

			HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

			URL url = new URL("https://www.google.com");

			HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
			urlConnection.connect();

		} 
		catch (Throwable t) {
			throw new RuntimeException(t);
		}
	}

}
