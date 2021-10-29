package com.horasan;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.operator.OperatorCreationException;

import com.horasan.utils.Utils;

import entity.CryptoEnvironment;
import entity.CryptoPackage;
import entity.CryptoUser;

public class CryptoCommunicationExample {
	
	public static void main(String[] args) {
		
		Utils.logMessage(Utils.SINGLE_TAB, "STEP [0] -------------");
		CryptoEnvironment cryptoEnvironment = new CryptoEnvironment("internet");
		CryptoUser messageSenderUserAlice = new CryptoUser("alice");
		CryptoUser messageReceieverUserBob = new CryptoUser("bob");
		
		// [1] users and their public information are known to the environment.
		Utils.logMessage(Utils.SINGLE_TAB, messageSenderUserAlice, "I am known to the enviroment.");
		cryptoEnvironment.addUser(messageSenderUserAlice.getUserEndPoint(), messageSenderUserAlice);
		
		Utils.logMessage(Utils.SINGLE_TAB, messageReceieverUserBob, "I am known to the enviroment.");
		cryptoEnvironment.addUser(messageReceieverUserBob.getUserEndPoint(), messageReceieverUserBob);
		
		Utils.logMessage(Utils.SINGLE_TAB, "STEP [1] -------------");
		
		try {
			//Alice wants to send a secret message to bob.
			Utils.logMessage(Utils.SINGLE_TAB, messageSenderUserAlice, "I want to send a secret message to " + "bob");
			// So Alice encrypts the secret message with Bob's public key...
			CryptoPackage cryptoPackageFromAliceToBob = messageSenderUserAlice.generateCryptoPackageFor("bob");
					
			// Alice wants to send a CryptoMessage to bob via CryptoEnvironment.
			messageSenderUserAlice
			.getRegisteredEnvironment()
			.sendCryptoPackage("alice", "bob", cryptoPackageFromAliceToBob);
			
			Utils.logMessage(Utils.SINGLE_TAB, "---------");
			Utils.logMessage(Utils.SINGLE_TAB, messageSenderUserAlice.getUserEndPoint() + " sent:\t\t" + messageSenderUserAlice.getOriginalMessage());
			Utils.logMessage(Utils.SINGLE_TAB, messageReceieverUserBob.getUserEndPoint() + " received:\t\t" + messageSenderUserAlice.getOriginalMessage());
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | SignatureException
				| IllegalBlockSizeException | BadPaddingException e) {
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

}
