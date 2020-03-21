//Name: Hung Siew Kee
//Student ID: 5986606

import java.util.*;
import java.math.*;
import java.io.*;

public class Gen
{
	//static BigInteger value of 1 and 2
	static BigInteger one = new BigInteger("1");
	static BigInteger two = new BigInteger("2");

	public static void main (String args[])
	{
		// set min value to be 32 bit
		BigInteger b_int = new BigInteger ("2147483647");
		
		//initialise the next prime number
		BigInteger b_int_s_prime = b_int.nextProbablePrime();
		boolean check_s_prime = false;
		
		//while loop until the next prime is a safe prime
		while (check_s_prime == false)
		{
			check_s_prime = isSafePrime(b_int_s_prime);
			if (!check_s_prime)
				b_int_s_prime = b_int_s_prime.nextProbablePrime();	
		}
		
		//calculate primitive root with establised safe prime
		BigInteger pri_root = calculatePRoot(b_int_s_prime);
		
		//write on text file under both directories
		writeFile("Alice/Shared.txt", b_int_s_prime, pri_root);
		writeFile("Bob/Shared.txt", b_int_s_prime, pri_root);
		
		System.out.println("Generated: Safe Prime and Generator \nReady for secure connection");	
	}

	public static boolean isSafePrime(BigInteger p)
	{
		boolean safePrime_check = false;
		
		//calculate (p-1)/2
		BigInteger test = p.subtract(one);
		test = test.divide(two);
		
		//verify if parameter p is safe prime by checking if calculated (p-1)/2 is prime
		// subtract calculated value by 1 and use next Probable Prime function
		BigInteger test_check = test.subtract(one);
		BigInteger test_check_next_prime = test_check.nextProbablePrime();
		
		if (test.equals(test_check_next_prime))
			safePrime_check = true;
			
		return safePrime_check;
	}
	
	public static BigInteger calculatePRoot(BigInteger p)
	{
		//calculate exopnent value (p-1)/2
		BigInteger exponent_val = p.subtract(one);
		exponent_val = exponent_val.divide(two);
		
		//random biginteger with value less than p
		Random rand = new Random();
    	BigInteger b_int_rand = new BigInteger(p.bitLength(), rand);
    	BigInteger p_root = b_int_rand;
    	
    	//pow mod with random number
		BigInteger check_p_root = p_root.modPow(exponent_val, p);
		
		//if pow mod value = 1, then mod p with the negative value of random number
		if (check_p_root.equals(one))
		{
			BigInteger p_root_neg = b_int_rand.negate();
			p_root = p_root_neg.mod(p);
		}
			
		return p_root;		
	}
	
	public static void writeFile(String fileName, BigInteger p, BigInteger g)
	{
		//convert BigInteger value to string
		String prime = p.toString();
		String gen = g.toString();
		
		// If the file exists, append to it
		File file = new File(fileName);
		try (FileWriter writer = new FileWriter(file, true);
		BufferedWriter bw = new BufferedWriter(writer))
		{
			bw.write(prime + "\n");
			bw.write(gen);
		} 
		catch (IOException e) 
		{
			System.err.format("IOException: %s%n", e);
		}
	}
}
