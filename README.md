# hawk
CSEC 750 Evil Bit C2

## Implementation

This C2 communicates by writing 3 bits at a time to TCP packets, utilizing the reserved header

## Usage
Run the Server on the box you want to recieve the message on. </br>
Run the Client on the box you want to send the message from.

Enter your message, and it will send the message to the server.
You can run the client multiple times to send multiple messages. 


## Structure
The Client, Config, Lib, and Server are all used for basic communications. 
The MITM library can be used in a MITM Server implementation. 
The POC*.py libraries were only used for testing one off functions.