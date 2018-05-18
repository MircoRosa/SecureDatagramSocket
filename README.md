# Secure Datagram Socket 
SecureDatagramSocket is a library that allows to send and receive encrypted data between entities using Diffie-Hellman key exchange scheme, AES and more.

## Usage
Here is a basic example of how the library can be used. For a more complex use case, refer to Alice and Bob classes included in the project.

#### Connection Establishment
First of all, a connection between the two parts must be established.

Bob waits for requests simply using
```java
socket.waitDHSetup();
```
while Alice can try to establish a connection with
```java
socket.askDHSetup("Alice",IPAddress,Prefs.BOB_PORT);
```
The Diffie-Hellman handshake is then executed; if it succeeds, connection is established and messages can be exchanged securely.

#### Message Exchange
A new message can be sent simply using
```java
socket.secureSend(plainPacket);
```
while the recipient must be waiting for new messages with
```java
socket.secureReceive(plainPacket);
```
The entire encryption process is blackboxed, and users only have to give plain text as input.

#### Closing the connection
The connection can be closed by both sender and receiver using
```java
socket.close();
```
#
_This library has been developed for the "Network Security" Master's Degree course @University of Parma._