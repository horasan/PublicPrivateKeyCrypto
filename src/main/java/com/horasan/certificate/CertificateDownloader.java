package com.horasan.certificate;

import java.io.IOException;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.net.ssl.HttpsURLConnection;

import com.horasan.utils.Utils;

public class CertificateDownloader {

	public static void main(String[] args) throws IOException {
		String httpsURL = "https://www.google.com/";
		downloadCertificates(httpsURL);
	}

	public static void downloadCertificates(String httpsURL) throws IOException {

		URL connectionURL = new URL(httpsURL);
		HttpsURLConnection conn = (HttpsURLConnection) connectionURL.openConnection();
		
		Utils.logMessage(Utils.SINGLE_TAB, "Sending " + conn.getRequestMethod() + " request to " + httpsURL);
		
		Utils.logMessage(Utils.DOUBLE_TAB, "HTTP Response code is " + conn.getResponseCode());
		Utils.logMessage(Utils.DOUBLE_TAB, "Cipher Algorithm: " + conn.getCipherSuite());
		
		Utils.logMessage(Utils.SINGLE_TAB, "--------");
		Certificate[] certificateList = conn.getServerCertificates();
		
		Utils.logMessage(Utils.SINGLE_TAB, "Printing certificate information. # of certificates is " + certificateList.length);
		
		int index = 1;
		PublicKey publicKey = null;
		
		for (Certificate certificate : certificateList) {
			
			Utils.logMessage(Utils.SINGLE_TAB, "Certificate [" + index + "]");
			Utils.logMessage(Utils.SINGLE_TAB, "Cert Type\t\t: " + certificate.getType());
			Utils.logMessage(Utils.SINGLE_TAB, "Cert Hash Code\t\t: " + certificate.hashCode());

			Utils.logMessage(Utils.SINGLE_TAB, "Printing Public Key information: ");
			publicKey = certificate.getPublicKey();
			Utils.logMessage(Utils.DOUBLE_TAB, "Algorithm\t: " + publicKey.getAlgorithm());
			Utils.logMessage(Utils.DOUBLE_TAB, "Format\t\t: " + publicKey.getFormat());
			Utils.logMessage(Utils.DOUBLE_TAB, "All Info\t: " + certificate.getPublicKey());

			index++;
			Utils.logMessage(Utils.DOUBLE_TAB, "--------");
		}
	}
}
