package entity;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.horasan.utils.Utils;

public class CryptoEnvironment {
	
	// https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
	public static String cipherTransformationName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
	public static String keyPairGeneratorAlgorithm = "RSA";
	public static String hashingAlgorithm = "SHA256withRSA";
	public static int rsaKeySize = 2048;
	public String name;
	public Map<String, CryptoUser> userList;
	
	
	public CryptoEnvironment(String name) {
		userList = new HashMap<>();	
		this.name = name;
	}
	
	public void addUser(String userEndPoint, CryptoUser user) {
		user.registerEnvironment(this);
		userList.put(userEndPoint, user);
	}
	
	public void sendCryptoPackage(String senderUserEndPoint, String receiverUserEndPoint, CryptoPackage cryptoPackage) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		Utils.logMessage(Utils.SINGLE_TAB, "STEP [2] -------------");
		Utils.logMessage(Utils.SINGLE_TAB, this, "I received a call request from " + senderUserEndPoint + " to " + receiverUserEndPoint);
		
		Utils.logMessage(Utils.SINGLE_TAB, this, "I know who '" + receiverUserEndPoint + "' is");
		CryptoUser messageReceieverUser = userList.get(receiverUserEndPoint);
		
		Utils.logMessage(Utils.SINGLE_TAB, this, "It is OK if third parties see the message.");
		Utils.logMessage(Utils.SINGLE_TAB, this, "The message is : " + new String(cryptoPackage.getEncryptedMessageBytes()));
		Utils.logMessage(Utils.SINGLE_TAB, this, "I have forwarded the call request to '" + receiverUserEndPoint + "'.");
		messageReceieverUser.receiveCryptoPackage(senderUserEndPoint, cryptoPackage);
		
	}

	public Certificate getCertificateFor(String userEndPoint) {
		
		return userList.get(userEndPoint).getCertificate();
	}

	public String getName() {
		return name;
	}
	
}
