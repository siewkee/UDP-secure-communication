//Name: Hung Siew Kee
//Student ID: 5986606

import java.io.*;
import java.math.*;
import java.util.*;
import java.util.regex.*;
import java.net.*;
import java.security.*;

public class Server_Alice
{
	private static DatagramSocket socket;
	private static DatagramPacket incoming_packet;
	private static DatagramPacket outgoing_packet;
	
	private static int PORT;
	
	//static BigInteger value of 1 and 2
	private static BigInteger one = new BigInteger("1");
	private static BigInteger two = new BigInteger("2");
	
	public static void main (String [] args)  throws Exception 
	{
		//read file to get pw, p and g
		String stored_text[] = new String[3];
		String fileName = "Shared.txt";
		readFile(fileName, stored_text);
		
		String password = stored_text[0];
		BigInteger p = new BigInteger(stored_text[1]);
		BigInteger g = new BigInteger(stored_text[2]);
		
		//establish UDP connection & key exchange
		System.out.println("Pending new connection request ...");
				
		//Host is running and listening to the opened port 
		PORT = 1502;
		socket = new DatagramSocket(PORT);
		incoming_packet = new DatagramPacket(new byte[512],512);
				
		//Receive connection request from Client
		socket.receive(incoming_packet);
		String connnect_req = new String(incoming_packet.getData(), 0, incoming_packet.getLength());
		System.out.println("Client:\t" + connnect_req);
		
		while(true)
		{
		 	//Alice generates a random x
			BigInteger XA = generateSecretKey(p);
			System.out.println("######## Generated Alice's part of shared session key ########");
			
			//XA = gX mod p	
			BigInteger XA_DiffiHel = DiffiHellman(XA, p, g);
			String XA_DiffiHel_str = XA_DiffiHel.toString();
			System.out.println("Alice's DiffHel Key:\t" + XA_DiffiHel.toString());
		 		
		 	//Epw = gX mod p
			byte XA_DiffiHel_byte[] = XA_DiffiHel_str.getBytes();
			byte XA_DiffiHel_encrypted[]  = RC4_SecretKey(XA_DiffiHel_byte, password);
			System.out.println("Alice's DiffHel Key encrypted:\t" + XA_DiffiHel_encrypted.toString());
		 		
		 	//send Epw = gX mod p to Client.
		 	outgoing_packet = new DatagramPacket(XA_DiffiHel_encrypted, 0, XA_DiffiHel_encrypted.length, incoming_packet.getAddress(), incoming_packet.getPort());
			socket.send(outgoing_packet);
			System.out.println("######## Encrypted Alice's DiffHel Key sent to Client ########");
			
			//Receive Client's Epw = gY mod p
			incoming_packet = new DatagramPacket(new byte[512],512);
			socket.receive(incoming_packet);
			System.out.println("######## Received Client's encrypted DiffHel Key ########");
	
			//Dpw = gY mod p
			byte YC_DiffiHel_encrypted[] = incoming_packet.getData();
			System.out.println("Client's DiffHel Key Encrypted:\t" + YC_DiffiHel_encrypted.toString());
			
			String YC_DiffiHel_decrypted_str = new String(RC4_SecretKey(YC_DiffiHel_encrypted, password), 0, incoming_packet.getLength());
			System.out.println("Client's DiffHel Key Decrypted:\t" + YC_DiffiHel_decrypted_str);
				
			//K = H(gXY mod p)
			BigInteger YC_DiffiHel = new BigInteger(YC_DiffiHel_decrypted_str);
			BigInteger shared_sess_key = DiffiHellman(XA, p, YC_DiffiHel);
			String shared_sess_key_str = shared_sess_key.toString();
			
			String shared_sess_key_h = SHA1(shared_sess_key_str);
			System.out.println("######## Established Shared Session Key. Channel is secured. ########");
			
			while(true)
			{
				System.out.println();
				Scanner console = new Scanner(System.in);
				System.out.print("Enter message: ");
				String message = console.nextLine();
				
					//add delimiter
					String message_delimit = message.concat("-");
					
					//H = Hash(K||M)
					String hash = SHA1(message_delimit.concat(shared_sess_key_h));
					
					//C = Ek(H||M)
					String hash_message = message_delimit.concat(hash);
					byte hash_message_byte[] = hash_message.getBytes();
					byte hash_encrypted[] = RC4_SecretKey(hash_message_byte, shared_sess_key_h);
					
					//send C = Ek(H||M) to Client via UDP		
					outgoing_packet = new DatagramPacket(hash_encrypted, 0, hash_encrypted.length, incoming_packet.getAddress(), incoming_packet.getPort());
					socket.send(outgoing_packet);
					
					if (message.length() > 1)
						System.out.println("Cipher sent to client:\t" + hash_encrypted.toString());
				
				if (message.equalsIgnoreCase("exit")) 
				{
					socket.close();
					System.out.println("######## Request channel to be terminated ########");
					System.exit(1);
				}
				
				//receive C = Ek(H||M) from Client via UDP
				incoming_packet = new DatagramPacket(new byte[512],512);
				socket.receive(incoming_packet);
				byte[] encrypted_message_rec = incoming_packet.getData();
				System.out.println("Cipher text received from client:\t" + encrypted_message_rec.toString());
				
				//M||H = Dk(C)
				String hash_decrypted_str = new String(RC4_SecretKey(incoming_packet.getData(), shared_sess_key_h), 0, incoming_packet.getLength());
				
				//H’ = Hash(K||M)
				//check if H = H'
				String[] tokens = hash_decrypted_str.split(Pattern.quote("-"));
				String message_decrypted = tokens[0];
				String message_decrypted_delimit = tokens[0].concat("-");
				
				String hash_prime = SHA1(message_decrypted_delimit.concat(shared_sess_key_h));
				
				if (message_decrypted.equalsIgnoreCase("exit"))
				{
					socket.close();
					System.out.println("######## Client has request channel to be terminated ########\n######## Session has ended ########");
					System.exit(1);
				}
				// if calculated hash_prime equals decrypted hash
				else if(hash_prime.equals(tokens[1]))
				{
					System.out.println("######## Alice accepts the message ########");
					System.out.println("Received message:\t" + message_decrypted);
				}
				else
					System.out.println("######## Decryption error ########");	
			}
		}
		
	}
	
	public static void readFile(String fileName, String array[])
	{
		File file = new File(fileName);
		try(BufferedReader br = new BufferedReader (new FileReader(file));)	
		{
			int i = 0;
			while (i < array.length)
			{
				array[i] = br.readLine();
				i++;
			}
		}
		catch (IOException e) 
		{
			System.err.format("IOException: %s%n", e);
		}
	}
	
	public static BigInteger generateSecretKey(BigInteger p)
	{
		//random X (Alice's part of Shared Session Key)
		//more than 1 but less than safe prime
		Random rand = new Random();
		BigInteger X;
		
		do
		{
		 	X = new BigInteger(32, rand);
		}while (X.compareTo(p) >= 0 || X.equals(one));
		
		return X;
	}
	
	public static BigInteger DiffiHellman(BigInteger SecretKey, BigInteger p, BigInteger g)
	{
		BigInteger SecretKey_DifHel;
		return SecretKey_DifHel = g.modPow(SecretKey, p);
	}
	
	public static byte[] RC4_SecretKey(byte SKey_DifHel[], String password)
	{
		//decrypt or encrypt with password using RC4
		RC4 crypto_bitstream = new RC4(password.getBytes());
		byte SKey_DifHel_de_encrypted[] = crypto_bitstream.encrypt(SKey_DifHel);
			
		return SKey_DifHel_de_encrypted;
		
	}
	
	//source: http://www.sha1-online.com/sha1-java/
	public static String SHA1(String input) throws NoSuchAlgorithmException
	{
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        
        for (int i = 0; i < result.length; i++)
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
         
        return sb.toString();
   }
    
    
}




