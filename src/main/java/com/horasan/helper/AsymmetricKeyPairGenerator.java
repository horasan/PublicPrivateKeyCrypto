package com.horasan.helper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class AsymmetricKeyPairGenerator {
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException {
		int rsaKeySize = 2048;
		// RSA: from https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
		final KeyPair keyPair = getAsymmetricKeyPair("RSA", rsaKeySize);
		
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();
		
		// print the keys to console
		System.out.println("Public Key: " + publicKey);
		System.out.println("Private Key: " + privateKey);
		
	}
	
	public static KeyPair getAsymmetricKeyPair(String keyPairGeneratorAlgorithm, int keySize) throws NoSuchAlgorithmException {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyPairGeneratorAlgorithm);
		keyPairGenerator.initialize(keySize);
		return keyPairGenerator.generateKeyPair();
	} 
	
}
