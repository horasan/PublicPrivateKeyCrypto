package com.horasan.utils;

import entity.CryptoEnvironment;
import entity.CryptoUser;

public class Utils {

	public static String SINGLE_TAB = "\t";
	public static String DOUBLE_TAB = "\t\t";

	public static void logMessage(String indent, CryptoUser loggingUser, String message) {

		String from = "[" + loggingUser.getUserEndPoint() + "]";

		System.out.println(indent + from + ": " + message);
	}

	public static void logMessage(String indent, CryptoEnvironment environment, String message) {

		String from = "[" + environment.getName() + "]";

		System.out.println(indent + from + ": " + message);
	}
	
	public static void logMessage(String indent, String message) {
		System.out.println(indent + message);
	}
	
	public static void logMessage(String message) {
		System.out.println(Utils.SINGLE_TAB + message);
	}

}
