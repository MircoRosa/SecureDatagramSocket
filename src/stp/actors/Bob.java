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
 * Bob, who wants to communicate safely with Alice.
 */
public class Bob {

	private SecureDatagramSocket socket;
	private InetAddress IPAddress;
	private static final Logger LOG = Logger.getLogger("BOB");


	private Bob() throws IOException {
		setupLogger(LOG);
		LOG.setLevel(Prefs.LOG_LEVEL);
		socket = new SecureDatagramSocket(Prefs.BOB_PORT);
		IPAddress = InetAddress.getByName(Prefs.LOCAL_ADDRESS);
		LOG.info("Initialization done.");
	}

	private void waitForDHSetup() throws Exception {
		LOG.info("Waiting for handshaking with Alice...");
		socket.waitDHSetup();
	}

	private void secureReceiveFromAlice() {
		LOG.info("Waiting for message from Bob...");
		byte[] buffer = new byte[Prefs.PACKET_SIZE];
		DatagramPacket plainPacket = new DatagramPacket(buffer,Prefs.PACKET_SIZE);
		String plaintext = socket.secureReceive(plainPacket);
		System.out.println("ALICE: "+plaintext);
	}

	private void secureSendToAlice() {
		Scanner scanner = new Scanner(System.in);
		byte[] buffer = new byte[Prefs.PACKET_SIZE];
		DatagramPacket plainPacket = new DatagramPacket(buffer,Prefs.PACKET_SIZE, IPAddress,Prefs.ALICE_PORT);
		System.out.print("ME: ");
		LOG.info("Sending message to Alice...");
		plainPacket.setData(scanner.nextLine().getBytes());
		socket.secureSend(plainPacket);
		LOG.info("Message sent to Alice.");
	}

	private void closeSession() {
		socket.close();
		LOG.info("Session closed.");
	}

	public static void main(String[] args) throws Exception {
		Bob bob = new Bob();

		bob.waitForDHSetup();

		//Simple chat for testing
		for (int i = 0; i < Prefs.CHAT_LENGTH; i++) {
			bob.secureReceiveFromAlice();
			bob.secureSendToAlice();
		}
		bob.closeSession();
	}

	private void setupLogger(Logger logger) {
		logger.setUseParentHandlers(false);
		LogFormatter formatter = new LogFormatter();
		ConsoleHandler handler = new ConsoleHandler();
		handler.setFormatter(formatter);
		logger.addHandler(handler);
	}
}
