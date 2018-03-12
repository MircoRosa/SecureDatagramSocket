package stp;

import java.util.logging.Level;

/**
 * Global parameters of the project.
 */
public class Prefs {

	/*NETWORK PARAMETERS*/
	public static final int ALICE_PORT = 10001;
	public static final int BOB_PORT = 10002;
	public static final String LOCAL_ADDRESS = "127.0.0.1";

	/*PROTOCOL PARAMETERS*/
	public static final int PACKET_SIZE = 1024;

	/*KEY EXCHANGE PARAMETERS*/
	public static final int KEY_LENGTH = 512;
	public static final int EXPONENT_SIZE = 8;

	/*MISC*/
	public static final Level LOG_LEVEL = Level.ALL;
	public static final int CHAT_LENGTH = 3;



}
