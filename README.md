# payglocal-java-sdk

This is the Java reference implementation to generate token to process test transaction on PayGlocal platform. 

This package primarily have follwoing two main classes 
JWS.java => this helps generate JWS token which is passed in http header 'x-gl-token-external'
JWE.java => this helps to encrypt the payload which passed as body of the request.

The resources package contains keys folder where you need to place the PayGlocal public key and Your private key
There is file requestpayload.json which you can use send payload.

Start off from the Main.java class to understand the integration specs.
Modify the keys and payload file location according to your local configuration. 

Once you run the main function you will get following two tokens which can be used to initiate payment request at PayGlocal platform
"JWE token for transaction = <JWE_TOKEN_VALUE> "
"JWS token for transaction = <JWS_TOKEN_VALUE> "

pass JWS_TOKEN_VALUE in the http header 'x-gl-token-external'
pass JWE_TOKEN_VALUE in the http body





