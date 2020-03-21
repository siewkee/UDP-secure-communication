Implementation Logic
=================================
• Place Host and Client in two separate directories: Alice and Bob. The shared information (PW, p, g) is put in a text file under each directory.
• Alice executes Host.
- Host is running and listening to the opened port (you need to select a port for your code).
• Bob executes Client.
- Client (Bob) sends a connection request to Host.
- Client is ready and listens to the port.
• Host generates a random x, computes gx mod p, encrypts it using RC4, and sends the ciphertext to Client.
• Upon receiving the message from the Host, Client decrypts the message to obtain gx mod p. Client also generates and sends the encryption of gy mod p to Host. Client then computes the shared key K.
• Upon receiving the message from Client, Host performs the decryption to obtain gy mod p and then computes the shared key K.
• Now, the secure channel is established.

Either Alice or Bob can send a message encrypted and authenticated by the key K. They type the message on their own terminal. The message is processed by their code (Host or Client) according to the step 2 given above.

The received message is printed on the screen if decryption is successful. Otherwise, print “decryption error” on the screen.




Shared Password
=================================
Password stored in Shared.txt of both Alice and Bob's folder


Compile & Execute
=================================
//generate safe prime and generator with Gen.java
//both alice's and bob's text file will be updated
1.		javac Gen.java
2.		java Gen

//route to Alice's and Bob's folder
//compile RC4.java to create the class first
//compile Alice and Bob's code
2.		javac RC4.java
3.		javac Server_Alice.java
4.		javac Client_Bob.java

//always ensure that host is executed first before client	
5.		java Server_Alice
6.		java Client_Bob


Note
=================================
- Once the secure channel is establised, this will be annouced on both Alice's and Bob's terminal.
- Both Alice and Bob's terminal will be expecting message input constantly. 
- If Alice sends a message to Bob, Bob can either 
	1) send a message across at the same time. Both Alice and Bob will decrypt received message at the same time.
	2) OR choose not to send any message. Hit "enter" button instead to just receive and decrypt message from Alice.
- Same sequence when Bob sends a message to Alice

- Either Bob of Alice can initiate termination by input "exit".
 
- If the password needs to be changed, please ensure that the cursor is at first line at the end of the password string. This allows Gen.java to update the text with P and G in the next lines. Otherwise, there will be error reading the file to extract these values subsequently.

- Program is written Ubuntu environment and executed in terminal.


Directory
=================================
A1
	>> Instructions.txt
	>> Gen.java
	> Alice
		>> RC4.java
		>> Server_Alice.java
		>> Shared.txt
	> Bob
		>> RC4.java
		>> Client_Bob.java
		>> Shared.txt







