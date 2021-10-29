package entity;

import lombok.Getter;

@Getter
public class CryptoPackage {

	private byte[] encryptedMessageBytes;
	private byte[] messageSignature;
	
	public CryptoPackage(byte[] encryptedMessageBytes, byte[] messageSignature) {
		this.encryptedMessageBytes = encryptedMessageBytes;
		this.messageSignature = messageSignature;
	}
	
}

