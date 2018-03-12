package stp.actors;

import stp.Prefs;
import stp.api.SecureDatagramSocket;
import stp.libs.LogFormatter;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.Scanner;
import java.util.logging.ConsoleHandler;
import java.util.logging.Logger;

/**
 * Alice, who wants to communicate safely with Bob.
 */
public class Alice {

	private SecureDatagramSocket socket;
	private InetAddress IPAddress;
	private static final Logger LOG = Logger.getLogger("ALICE");

	private Alice() throws IOException {
		setupLogger(LOG);
		LOG.setLevel(Prefs.LOG_LEVEL);
		socket = new SecureDatagramSocket(Prefs.ALICE_PORT);
		IPAddress = InetAddress.getByName(Prefs.LOCAL_ADDRESS);
		LOG.info("Initialization done.");
	}

	private void secureSendToBob() {
		Scanner scanner = new Scanner(System.in);
		byte[] buffer = new byte[Prefs.PACKET_SIZE];
		DatagramPacket plainPacket = new DatagramPacket(buffer,Prefs.PACKET_SIZE, IPAddress,Prefs.BOB_PORT);
		System.out.print("ME: ");
		LOG.info("Sending message to Bob...");
		plainPacket.setData(scanner.nextLine().getBytes());
		socket.secureSend(plainPacket);
		LOG.info("Message sent to Bob.");
	}

	private void secureReceiveFromBob() {
		LOG.info("Waiting for message from Bob...");
		byte[] buffer = new byte[Prefs.PACKET_SIZE];
		DatagramPacket plainPacket = new DatagramPacket(buffer,Prefs.PACKET_SIZE);
		String plaintext = socket.secureReceive(plainPacket);
		System.out.println("BOB: "+plaintext);
	}

	private void askForDHSetup() throws Exception {
		LOG.info("Starting handshaking with Bob...");
		socket.askDHSetup("Alice",IPAddress,Prefs.BOB_PORT);
	}

	private void closeSession() {
		socket.close();
		LOG.info("Session closed.");
	}

	public static void main(String[] args) throws Exception {
		Alice alice = new Alice();

		alice.askForDHSetup();

		//Simple chat for testing
		for (int i = 0; i < Prefs.CHAT_LENGTH; i++) {
			alice.secureSendToBob();
			alice.secureReceiveFromBob();
		}

		alice.closeSession();
	}

	private void setupLogger(Logger logger) {
		logger.setUseParentHandlers(false);
		LogFormatter formatter = new LogFormatter();
		ConsoleHandler handler = new ConsoleHandler();
		handler.setFormatter(formatter);
		logger.addHandler(handler);
	}
}
