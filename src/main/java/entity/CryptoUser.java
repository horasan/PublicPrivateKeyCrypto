package entity;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.horasan.helper.AsymmetricKeyPairGenerator;
import com.horasan.utils.Utils;

public class CryptoUser {
	
	private CryptoEnvironment cryptoEnvironment;
	private KeyPair keyPair;
	private String originalMessage;
	private String decryptedMessage;
	private Certificate certificate;
	private String userEndPoint;
	
	public CryptoUser(String userEndPoint) {
		
		this.userEndPoint = userEndPoint;
		
		try {
			keyPair = AsymmetricKeyPairGenerator.getAsymmetricKeyPair(CryptoEnvironment.keyPairGeneratorAlgorithm, CryptoEnvironment.rsaKeySize);
			certificate = generateCertificate();
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public CryptoEnvironment registerEnvironment(CryptoEnvironment cryptoEnvironment) {
		this.cryptoEnvironment = cryptoEnvironment;
		return cryptoEnvironment;
	}
	
	public String getUserEndPoint() {
		return userEndPoint;
	}
	
	public CryptoEnvironment getRegisteredEnvironment() {
		return cryptoEnvironment;
	}
	
	public PublicKey getPublicKey() {
		return this.keyPair.getPublic();
	}
	
	private PrivateKey getPrivateKey() {
		return this.keyPair.getPrivate();
	}
	
	public Certificate getCertificate() {
		return this.certificate;
	}
	
	public String getOriginalMessage() {
		return originalMessage;
	}
	
	public String getDecryptedMessage() {
		return decryptedMessage;
	}

public CryptoPackage generateCryptoPackageFor(String receiverUserEndPoint) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException, CertificateException, OperatorCreationException {
	
		String originalMessageToEncrypt = "1001_1002_1003";
		this.originalMessage = originalMessageToEncrypt; 
		Utils.logMessage(Utils.DOUBLE_TAB, this, "My secret message is: " + originalMessageToEncrypt);
		
		final byte[] originalBytes = originalMessageToEncrypt.getBytes(StandardCharsets.UTF_8);

		

		// alice is encrypting message with Bob' s public key!
		Utils.logMessage(Utils.DOUBLE_TAB, this, "I will use " + receiverUserEndPoint +  "'s 'Public Key' to encrypt the message.");
		Utils.logMessage(Utils.DOUBLE_TAB, this, "so I have downloded " + receiverUserEndPoint +  "'s certificate from environment.");
		Certificate receiverUserCertificate = this.getRegisteredEnvironment().getCertificateFor(receiverUserEndPoint); //this.downloadCertificateFor(receiverUser);

		Cipher rsaCipher = Cipher.getInstance(CryptoEnvironment.cipherTransformationName);
		rsaCipher.init(Cipher.ENCRYPT_MODE, receiverUserCertificate.getPublicKey());
		// encrypt the message
		byte[] encryptedMessageBytes = rsaCipher.doFinal(originalBytes);
		
		Utils.logMessage(Utils.DOUBLE_TAB, this, "I want " + receiverUserEndPoint + " to verify that the message is really prepared and sent by me.");
		Utils.logMessage(Utils.DOUBLE_TAB, this, "so I put a 'Signature' to the CryptoPackage. The 'Signature' is prepared using my own 'Private Key'.");
		byte[] messageSignature = createSignature(
											originalMessageToEncrypt.getBytes(StandardCharsets.UTF_8), 
											keyPair.getPrivate(), 
											CryptoEnvironment.hashingAlgorithm);
		
		return new CryptoPackage(encryptedMessageBytes, messageSignature);
	}

	private static byte[] createSignature(byte[] originalMessage,
			PrivateKey privateKey, String hashingAlgorithm) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		
		Signature signature = Signature.getInstance(hashingAlgorithm);
		signature.initSign(privateKey);
		// Alice is signing the encrypted message with her private key!
		// so Bob will be able to verify the message is sent by Alice!
		signature.update(originalMessage);
		byte[] signatureBytes = signature.sign();
		return signatureBytes;
		
	}

	public void receiveCryptoPackage(String senderUserEndPoint, CryptoPackage cryptoPackage) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		Utils.logMessage(Utils.SINGLE_TAB, "STEP [3] -------------");
		// What does the package include?
		byte[] encryptedMessage = cryptoPackage.getEncryptedMessageBytes();
		byte[] messageSignature = cryptoPackage.getMessageSignature();
		Utils.logMessage(Utils.SINGLE_TAB, this, "I have received a cryptoPackage from '" + senderUserEndPoint + "' (via '" + getRegisteredEnvironment().getName() + "')");

		Cipher rsaCipher = Cipher.getInstance(CryptoEnvironment.cipherTransformationName);

		// Bob is decrypting message with his private key.
		// The message was encrypted with Bob's public key by Alice.
		
		Utils.logMessage(Utils.SINGLE_TAB, this, "I will decrypt the message using my own 'Private Key'");
		rsaCipher.init(Cipher.DECRYPT_MODE, this.keyPair.getPrivate());
		byte[] decryptedMessageBytes = rsaCipher.doFinal(encryptedMessage);
		String calculatedDecryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
		Utils.logMessage(Utils.DOUBLE_TAB, this, "I am able to decrypt the message so I am sure that the message is sent to me.");
		
		Utils.logMessage(Utils.DOUBLE_TAB, this, "However I am not sure if the message is sent by '" + senderUserEndPoint + "'");
		Utils.logMessage(Utils.DOUBLE_TAB, this, "so I will verify the 'signature' using " + senderUserEndPoint + "'s 'Public Key'.");

		Utils.logMessage(Utils.SINGLE_TAB, this, "I will use " + senderUserEndPoint +  "'s 'Public Key' to verify the signature.");
		Utils.logMessage(Utils.DOUBLE_TAB, this, "so I have downloded " + senderUserEndPoint +  "'s certificate from environment.");		
		Certificate senderCertificate = getRegisteredEnvironment().userList.get(senderUserEndPoint).getCertificate();
		PublicKey senderPublicKey = senderCertificate.getPublicKey();
		Signature signature = Signature.getInstance(CryptoEnvironment.hashingAlgorithm);
		signature.initVerify(senderPublicKey);
		signature.update(decryptedMessageBytes);
		
		final boolean isSignatureValid = signature.verify(messageSignature);
		
		if (isSignatureValid) {
			Utils.logMessage(Utils.DOUBLE_TAB, this, "'Signature' is valid. The message is sent from '" + senderUserEndPoint + "'");
		}
		else {
			Utils.logMessage(Utils.DOUBLE_TAB, this, "'Signature' is NOT valid. The message is NOT sent from '" + senderUserEndPoint + "'");
		}
		
		this.decryptedMessage = calculatedDecryptedMessage;		
	}

	private Certificate generateCertificate() throws CertificateException, OperatorCreationException{

		String hashingAlgorithm = CryptoEnvironment.hashingAlgorithm;
		 X500Name certificateCommonName = new X500Name("cn=cert for asymmetricKeyPair");
		 
	        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded());
	        final Date startDate = new Date();
	        final Date endDate = Date.from(LocalDate.now().plus(365, ChronoUnit.DAYS).atStartOfDay().toInstant(ZoneOffset.UTC));
	        final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(certificateCommonName,
	                new BigInteger(10, new SecureRandom()),
	                startDate,
	                endDate,
	                certificateCommonName,
	                publicKeyInfo
	        );
	        ContentSigner signer = new JcaContentSignerBuilder(hashingAlgorithm).setProvider(new BouncyCastleProvider()).build(getPrivateKey());
	        X509CertificateHolder certificateHolder = builder.build(signer);

	        Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certificateHolder);
	        return cert;
	}
	
}
