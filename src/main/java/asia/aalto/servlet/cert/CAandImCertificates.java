/*
 * Created by Asad Javed on 20/05/2018
 * Aalto University project
 *
 * Last modified 20/05/2019
 */

package asia.aalto.servlet.cert;

import java.io.FileOutputStream;
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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class CAandImCertificates {

	public static void main(String[] args) throws Exception {

		Security.insertProviderAt(new BouncyCastleProvider(), 1);

		Certificate[] chainForCA = new Certificate[1];
		Certificate[] chainIntermediate = new Certificate[2];
		Certificate[] chainForServer = new Certificate[1];

		final char[] passwd = "password".toCharArray();  // Password for key store

		// CA certificate 
		KeyPair caKeyPair = generateKeyPair("RSA", 2048);	
		final PublicKey caPublicKey = caKeyPair.getPublic();
		final PrivateKey caPrivateKey = caKeyPair.getPrivate();
		chainForCA[0] = createCACertificate(caPublicKey, caPrivateKey);
		chainIntermediate[1] = chainForCA[0];

		// Intermediate certificate
		KeyPair imKeyPair = generateKeyPair("RSA", 2048);	
		final PublicKey imPublicKey = imKeyPair.getPublic();
		final PrivateKey imPrivateKey = imKeyPair.getPrivate();	
		chainIntermediate[0] = createIntermediatetCertificate((X509Certificate) chainForCA[0], caPrivateKey, imPublicKey);

		// Server Certificate
		KeyPair serverKeyPair = generateKeyPair("RSA", 2048);	
		final PublicKey serverPublicKey = serverKeyPair.getPublic();
		final PrivateKey serverPrivateKey = serverKeyPair.getPrivate();	
		chainForServer[0] = createServerCertificate(serverPublicKey, serverPrivateKey);


		KeyStore keyStore = KeyStore.getInstance("JKS");  // For storing self-signed CA and intermediate certificate 
		KeyStore keyStoreServer = KeyStore.getInstance("JKS");  // For storing CA of client and self-signed server certificate

		keyStore.load(null, passwd);
		keyStoreServer.load(null, passwd);

		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd);

		// Storing CA and intermediate certificates in keyStore
		KeyStore.PrivateKeyEntry caEntry = new KeyStore.PrivateKeyEntry(caPrivateKey, chainForCA);
		keyStore.setEntry("CA Entry", caEntry, protParam);
		KeyStore.PrivateKeyEntry imEntry = new KeyStore.PrivateKeyEntry(imPrivateKey, chainIntermediate);
		keyStore.setEntry("Intermediate Entry", imEntry, protParam);

		// Storing CA and self-signed server certificate in keyStoreServer
		keyStoreServer.setEntry("CA Entry", caEntry, protParam);
		KeyStore.PrivateKeyEntry serverEntry = new KeyStore.PrivateKeyEntry(serverPrivateKey, chainForServer);
		keyStoreServer.setEntry("Server Entry", serverEntry, protParam);


		FileOutputStream fileOutput = new FileOutputStream("D:/PHD-IoT/workspace/SecurityCertificate/configs/certKeyStore.jks");
		keyStore.store(fileOutput, passwd);

		FileOutputStream fileOutputS = new FileOutputStream("D:/PHD-IoT/workspace/SecurityCertificate/configs/serverStore.jks");
		keyStoreServer.store(fileOutputS, passwd);

		fileOutput.close();
		fileOutputS.close();

		System.out.println("KeyStore file successfully stored...");
	}


	/* Generate public private key pair */
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


	/* Create Certificate Authority CA */
	public static Certificate createCACertificate(PublicKey publicKey, PrivateKey privateKey) {

		try {

			// An alternative way to build X.500 Name for certificate
			X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
			nameBuilder.addRDN(BCStyle.CN, "Test Certificate Authority");	// RDN: Relative Distinguished Name
			nameBuilder.addRDN(BCStyle.OU, "AaltoAsia");
			nameBuilder.addRDN(BCStyle.O, "Aalto");
			nameBuilder.addRDN(BCStyle.L, "Espoo");
			nameBuilder.addRDN(BCStyle.ST, "Finland");
			nameBuilder.addRDN(BCStyle.C, "FI");

			X500Name issuerInfo = nameBuilder.build();
			X500Name subjectInfo = issuerInfo;

			// Strong random number generator for certificate serial number 
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			BigInteger serialNumber = BigInteger.valueOf(Math.abs(secureRandom.nextInt()));


			// Starting and expiry date for certificate
			Date startDate = new Date();
			Date expiryDate = new Date((startDate.getTime() + 365 * 24 * 60 * 60 * 1000L)); // 1 year validity

			// Build X.509 V1 certificate
			X509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder (
					issuerInfo, 
					serialNumber, 
					startDate, 
					expiryDate, 
					subjectInfo, 
					publicKey);

			// Create a signer and build and sign certificate
			ContentSigner signer = (ContentSigner) new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
			X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

			cert.checkValidity(new Date());
			cert.verify(publicKey);

			return cert;
		}
		catch (Throwable t) {
			throw new RuntimeException("Failed to create CA certificate. ", t);
		}
	}


	/* Create intermediate certificate that is signed by CA */
	public static Certificate createIntermediatetCertificate (X509Certificate caCert, PrivateKey caPrivateKey, PublicKey publicKey) {

		try {

			// An alternative way to build X.500 Name for certificate
			X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
			nameBuilder.addRDN(BCStyle.CN, "Intermediate Certificate");	// RDN: Relative Distinguished Name
			nameBuilder.addRDN(BCStyle.OU, "AaltoAsia");
			nameBuilder.addRDN(BCStyle.O, "Aalto");
			nameBuilder.addRDN(BCStyle.L, "Espoo");
			nameBuilder.addRDN(BCStyle.ST, "Finland");
			nameBuilder.addRDN(BCStyle.C, "FI");

			X500Name subjectInfo = nameBuilder.build();
			X500Name issuerInfo = new X509CertificateHolder(caCert.getEncoded()).getSubject();
			//X500Name subjectInfo = new X500Name(certName);

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
			certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(caCert.getPublicKey()));
			certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
			//KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature);
			//certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

			// Create a signer and build and sign certificate with CA private key
			ContentSigner signer = (ContentSigner) new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caPrivateKey);
			X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

			// Check certificate validity using date and public key
			cert.checkValidity(new Date());
			cert.verify(caCert.getPublicKey());

			return cert;
		}
		catch (Throwable t) {
			throw new RuntimeException("Failed to create self-signed certificate. ", t);
		}
	}

	/* Create a self-signed server certificate */
	public static Certificate createServerCertificate(PublicKey publicKey, PrivateKey privateKey) {

		try {

			// An alternative way to build X.500 Name for certificate
			X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
			nameBuilder.addRDN(BCStyle.CN, "localhost");	// RDN: Relative Distinguished Name
			nameBuilder.addRDN(BCStyle.OU, "AaltoAsia");
			nameBuilder.addRDN(BCStyle.O, "Aalto");
			nameBuilder.addRDN(BCStyle.L, "Espoo");
			nameBuilder.addRDN(BCStyle.ST, "Finland");
			nameBuilder.addRDN(BCStyle.C, "FI");

			X500Name issuerInfo = nameBuilder.build();
			X500Name subjectInfo = issuerInfo;

			// Strong random number generator for certificate serial number 
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			BigInteger serialNumber = BigInteger.valueOf(Math.abs(secureRandom.nextInt()));


			// Starting and expiry date for certificate
			Date startDate = new Date();
			Date expiryDate = new Date((startDate.getTime() + 365 * 24 * 60 * 60 * 1000L)); // 1 year validity

			// Build X.509 V1 certificate
			X509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder (
					issuerInfo, 
					serialNumber, 
					startDate, 
					expiryDate, 
					subjectInfo, 
					publicKey);

			// Create a signer and build and sign certificate
			ContentSigner signer = (ContentSigner) new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
			X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

			cert.checkValidity(new Date());
			cert.verify(publicKey);

			return cert;
		}
		catch (Throwable t) {
			throw new RuntimeException("Failed to create CA certificate. ", t);
		}
	}
}