/*
 * Created by Asad Javed on 20/05/2018
 * Aalto University project
 *
 * Last modified 20/05/2019
 */

package asia.aalto.servlet;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.eclipse.jetty.io.WriterOutputStream;

public class CreateCertificate extends HttpServlet {

	private static final long serialVersionUID = 1L;

	public void doPost(HttpServletRequest request, HttpServletResponse response)
	{
		try {
			//response.setContentType("application/x-x509-user-cert");
			response.setContentType("text/html");
			response.setStatus(HttpServletResponse.SC_OK);
			PrintWriter out = response.getWriter();

			Security.insertProviderAt(new BouncyCastleProvider(), 1);

			final char[] passwd = "password".toCharArray();  // Password for key store

			final String countryName = request.getParameter("country");
			final String stateName = request.getParameter("state");
			final String localityName = request.getParameter("locality");
			final String organizationName = request.getParameter("organization");
			final String organizationUnit = request.getParameter("organizationunit");
			final String commonName = request.getParameter("common");
			final String emailAddress = request.getParameter("emailaddress");

			X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE); 
			nameBuilder.addRDN(BCStyle.CN, commonName);	// RDN: Relative Distinguished Name
			nameBuilder.addRDN(BCStyle.OU, organizationUnit);
			nameBuilder.addRDN(BCStyle.O, organizationName);
			nameBuilder.addRDN(BCStyle.L, localityName);
			nameBuilder.addRDN(BCStyle.ST, stateName);
			nameBuilder.addRDN(BCStyle.C, countryName);
			nameBuilder.addRDN(BCStyle.EmailAddress, emailAddress);

			X500Name clientCertName = nameBuilder.build();

			FileInputStream fileIn = new FileInputStream("configs/certKeyStore.jks");

			KeyStore keyStore = KeyStore.getInstance("JKS");

			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd);

			keyStore.load(fileIn, passwd);

			KeyStore.PrivateKeyEntry certEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("Intermediate Entry", protParam);

			Certificate imCert = certEntry.getCertificate();
			PrivateKey imPrivateKey = certEntry.getPrivateKey();

			KeyPair clientKeyPair = ClientCertificate.generateKeyPair("RSA", 2048);
			PrivateKey clientPrivateKey = clientKeyPair.getPrivate();
			Certificate clientCert = ClientCertificate.createClientCertificate(clientCertName, clientKeyPair.getPublic(), (X509Certificate) imCert, imPrivateKey);

			out.println
			( "<html>"
					+ "<head>"
					+ "<title>Certificate</title>"
					+ "</head>"
					+ "<body>"
					+ "<h3>Certificate created successfully</h3> <br>"
					+ clientCert.toString()
					+ "</body>"
					+ "</html>"
					);

			System.out.println(clientCert);

			Certificate[] certChain = certEntry.getCertificateChain();
			Certificate[] finalChain = new Certificate[3];
			finalChain[2] = certChain[1];
			finalChain[1] = certChain[0];
			finalChain[0] = clientCert;

			//KeyStore clientStore = KeyStore.getInstance("PKCS12", "BC");
			//clientStore.load(null, null);
			//clientStore.setKeyEntry("Client Key", clientPrivateKey, null, finalChain);
			//FileOutputStream fileOut = new FileOutputStream("client.p12");
			//clientStore.store(fileOut, passwd);
			//clientStore.store(out, passwd);
			//OutputStream os = new WriterOutputStream(out);
			//clientStore.store(os, passwd);
			//out.print(finalChain.toString());
			//fileOut.close();
			fileIn.close();

		} 
		catch (Throwable t) {
			throw new RuntimeException(t);
		}
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
	{
		doPost(request, response);
	}

	private static class ClientCertificate {

		// Generate public private key pair
		public static KeyPair generateKeyPair(String algorithm, int size)
		{	
			try {
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");
				keyPairGenerator.initialize(size, new SecureRandom());
				KeyPair keyPair = keyPairGenerator.generateKeyPair();
				return keyPair;
			}
			catch (Throwable t) {
				throw new RuntimeException("Failed to generate key-pair. ", t);
			}
		}

		public static Certificate createClientCertificate (X500Name certName, PublicKey publicKey, X509Certificate imCert, PrivateKey imPrivateKey) {

			try {

				X500Name issuerInfo = new X509CertificateHolder(imCert.getEncoded()).getSubject();
				//X500Name subjectInfo = new X500Name(certName);

				X500Name subjectInfo = certName;

				// Strong random number generator for certificate serial number 
				SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
				BigInteger serialNumber = BigInteger.valueOf(Math.abs(secureRandom.nextInt()));

				// Starting and expiry date for certificate
				Date startDate = new Date();
				Date expiryDate = new Date((startDate.getTime() + 365 * 24 * 60 * 60 * 1000L)); // 1 year validity

				// Build X.509 V3 certificate
				X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder (
						issuerInfo, 
						serialNumber, 
						startDate, 
						expiryDate, 
						subjectInfo, 
						publicKey);

				// Adding extensions to the certificate
				JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();	
				certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(publicKey));
				certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(imCert.getPublicKey()));
				//certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
				KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature);
				certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

				// Create a signer and build and sign certificate with CA private key
				ContentSigner signer = (ContentSigner) new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(imPrivateKey);
				X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

				// Check certificate validity using date and public key
				cert.checkValidity(new Date());
				cert.verify(imCert.getPublicKey());

				return cert;
			}
			catch (Throwable t) {
				throw new RuntimeException("Failed to create self-signed certificate. ", t);
			}
		}
	}

}
