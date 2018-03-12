package stp.api;

import stp.Prefs;
import stp.libs.ByteUtils;
import stp.libs.LogFormatter;

import javax.crypto.*;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.*;
import java.util.Arrays;
import java.util.logging.ConsoleHandler;
import java.util.logging.Logger;

/**
 * Secure DatagramSocket library to ensure confidentiality.
 */
public class SecureDatagramSocket extends DatagramSocket {

	private static final Logger LOG = Logger.getLogger("SECURE_DS");

	private BigInteger p, g, x, my_y, other_y, ks;
	private byte[] realKey;
	
	public SecureDatagramSocket(int port) throws SocketException {
		super(port);
		setupLogger(LOG);
		LOG.setLevel(Prefs.LOG_LEVEL);
	}

	public void askDHSetup(String name, InetAddress address, int port) throws Exception {
		LOG.info("Starting Diffie-Hellman handshaking...");
		send(new DatagramPacket(name.getBytes(),name.getBytes().length,address,port));

		byte[] buffer = new byte[Prefs.PACKET_SIZE];
		DatagramPacket packet = new DatagramPacket(buffer,buffer.length);
		LOG.info("Waiting for DH parameters...");
		receive(packet);

		String parametersString = new String(getCleanData(packet));
		String[] DHParametersStrings = parametersString.split(":");
		LOG.info("DH parameters received.\n\tg="+DHParametersStrings[0]+"\n\tp="+DHParametersStrings[1]);
		g = new BigInteger(DHParametersStrings[0],16);
		p = new BigInteger(DHParametersStrings[1],16);
		DHParameterSpec DHParameters = new DHParameterSpec(p,g);


		LOG.info("Creating keys...");
		KeyPair keyPair = generateDhKeyPair(DHParameters);
		x=((DHPrivateKey)keyPair.getPrivate()).getX();
		my_y =((DHPublicKey)keyPair.getPublic()).getY();  //Public key to exchange
		LOG.info("Keys generated.\n\tx="+x.toString(16)+"\n\ty="+ my_y.toString(16));

		LOG.info("Sending public key...");
		send(new DatagramPacket(my_y.toByteArray(),my_y.toByteArray().length,address,port));
		LOG.info("Public key sent.");
		LOG.info("Waiting for public key...");

		Arrays.fill(buffer,(byte)0);
		receive(packet);
		other_y = new BigInteger(getCleanData(packet)); //Public key of the other party
		LOG.info("Public key received.\n\ty="+other_y.toString(16));

		ks = new BigInteger(computeDhSecret(keyPair,getPublicKey(p,g,other_y)));
		LOG.info("Shared Key:\n\tKs="+ks.toString(16)+" ("+ks.bitLength()+" bit)");

		generateKeyHash();
		LOG.info("Handshaking completed.");
	}

	public void waitDHSetup() throws Exception {
		LOG.info("Diffie-Hellman setup started...");
		DHParameterSpec DHParameters = generateDhParameters(Prefs.KEY_LENGTH);
		p = DHParameters.getP();
		g = DHParameters.getG();
		LOG.info("Parameters generated.");

		byte[] buffer = new byte[Prefs.PACKET_SIZE];
		DatagramPacket packet = new DatagramPacket(buffer,buffer.length);
		LOG.info("Waiting for someone to handshake with...");
		receive(packet);

		String name = new String(packet.getData());
		LOG.info("Starting Diffie-Hellman handshaking with "+name+"...");
		String paramsText = g.toString(16)+":"+p.toString(16);
		LOG.info("Sharing parameters...");
		send(new DatagramPacket(paramsText.getBytes(),paramsText.length(),packet.getAddress(),packet.getPort()));

		LOG.info("Creating keys...");
		KeyPair keyPair = generateDhKeyPair(DHParameters);
		x=((DHPrivateKey)keyPair.getPrivate()).getX();
		my_y =((DHPublicKey)keyPair.getPublic()).getY();  //Public key to exchange
		LOG.info("Keys generated.\n\tx="+x.toString(16)+"\n\ty="+ my_y.toString(16));

		LOG.info("Waiting for "+name+" public key...");
		Arrays.fill(buffer,(byte)0);
		receive(packet);
		other_y = new BigInteger(getCleanData(packet)); //Public key of the other party
		LOG.info(name+" public key received.\n\ty="+other_y.toString(16));
		LOG.info("Sending public key...");
		send(new DatagramPacket(my_y.toByteArray(),my_y.toByteArray().length,packet.getAddress(),packet.getPort()));
		LOG.info("Public key sent.");

		ks = new BigInteger(computeDhSecret(keyPair,getPublicKey(p,g,other_y)));
		LOG.info("Shared Key:\n\tKs="+ks.toString(16)+" ("+ks.bitLength()+" bit)");

		generateKeyHash();
		LOG.info("Handshaking completed.");
	}

	private static DHParameterSpec generateDhParameters(int k_len) throws Exception {
		LOG.info("Generating parameters...");
		AlgorithmParameterGenerator dh_param_gen=AlgorithmParameterGenerator.getInstance("DH");
		dh_param_gen.init(new DHGenParameterSpec(k_len,Prefs.EXPONENT_SIZE));
//		dh_param_gen.init(k_len);
		DHParameterSpec dh_param_spec=dh_param_gen.generateParameters().getParameterSpec(DHParameterSpec.class);
		LOG.info("Parameters generation completed.\n\tg="+dh_param_spec.getG().toString(16)+"\n\tp="+dh_param_spec.getP().toString(16));
		return dh_param_spec;
	}

	private static KeyPair generateDhKeyPair(DHParameterSpec dh_param_spec) throws Exception {
		KeyPairGenerator key_pair_gen=KeyPairGenerator.getInstance("DH");
		key_pair_gen.initialize(dh_param_spec);
		LOG.info("Generating DH KeyPair...");
		KeyPair key_pair=key_pair_gen.generateKeyPair();
		LOG.info("KeyPair generated.");
		return key_pair;
	}

	private static PublicKey getPublicKey(BigInteger p, BigInteger g, BigInteger other_y) throws Exception {
		KeyFactory dh_key_factory=KeyFactory.getInstance("DH");
		return dh_key_factory.generatePublic(new DHPublicKeySpec(other_y,p,g));
	}

	private static byte[] computeDhSecret(KeyPair key_pair, PublicKey y) throws Exception {
		KeyAgreement key_agree=KeyAgreement.getInstance("DH");
		key_agree.init(key_pair.getPrivate());
		key_agree.doPhase(y,true);
		return key_agree.generateSecret();
	}

	private void generateKeyHash() throws NoSuchAlgorithmException {
		byte[] message=ks.toByteArray();
		String algo="md5";
		MessageDigest md=MessageDigest.getInstance(algo);
		realKey=md.digest(message);
		LOG.info("Real key:\n\t"+ByteUtils.bytesToHexString(realKey));
	}


	/*
	* Symmetric key message exchange methods
	*/

	public void secureSend(DatagramPacket packet) {
		try {
			String log = "Encrypting and sending message...\n" +
					"\tPlaintext:  ("+packet.getData().length+" bytes) "+new String(packet.getData())+"\n";

			String algo="AES/ECB/PKCS5Padding";
			Cipher cipher = Cipher.getInstance(algo);
			String key_algo=algo.substring(0,algo.indexOf('/'));
			SecretKey secret_key=new SecretKeySpec(realKey,key_algo);

			cipher.init(Cipher.ENCRYPT_MODE,secret_key);
			byte[] ciphertext=cipher.doFinal(packet.getData());
			packet.setData(ciphertext);
			log+="\tCiphertext: ("+packet.getData().length+" bytes) "+ByteUtils.bytesToHexString(packet.getData());
			send(packet);
			LOG.info(log);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public String secureReceive(DatagramPacket packet) {
		try {
			receive(packet);
			String log = "Decrypting message...:\n"+
					"\tCiphertext: ("+ getCleanData(packet).length+" bytes) "+ByteUtils.bytesToHexString(getCleanData(packet))+"\n";

			String algo="AES/ECB/PKCS5Padding";

			Cipher cipher = Cipher.getInstance(algo);
			String key_algo=algo.substring(0,algo.indexOf('/'));
			SecretKey secret_key=new SecretKeySpec(realKey,key_algo);

			cipher.init(Cipher.DECRYPT_MODE,secret_key);
			byte[] plaintext = cipher.doFinal(getCleanData(packet));
			log+="\tPlaintext:  ("+plaintext.length+" bytes) "+new String(plaintext);
			LOG.info(log);
			return new String(plaintext);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private byte[] getCleanData(DatagramPacket packet) {
		byte[] cleanArray = new byte[packet.getLength()];
		System.arraycopy(packet.getData(),0,cleanArray,0,packet.getLength());
		return cleanArray;
	}

	private void setupLogger(Logger logger) {
		logger.setUseParentHandlers(false);
		LogFormatter formatter = new LogFormatter();
		ConsoleHandler handler = new ConsoleHandler();
		handler.setFormatter(formatter);
		logger.addHandler(handler);
	}
}
