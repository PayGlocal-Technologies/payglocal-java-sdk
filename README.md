This is the Java reference implementation to generate token to process test transaction on PayGlocal platform. 

JWS and JWE generation classes
```
1. JWS.java => this helps generate JWS token which is passed in http header 'x-gl-token-external'
2. JWE.java => this helps to encrypt the payload which passed as body of the request.
```

Resource package files
```
1. requestpayload.json which you can use generate JWS and JWE for transaction request.
2. altid_requestpayload.json which you can use generate JWS and JWE for alt id request.
3. compliance_check_requestpayload.json which you can use generate JWS and JWE for compliance API request.
4. keys folder where you need to place the PayGlocal public key and Your private key
```

Start off from the Main.java class to understand the integration specs.
```
Modify the keys and payload file location according to your local configuration. 
```

Output once you run the main.java
```
"JWE token for transaction = <JWE_TOKEN_VALUE> "
"JWS token for transaction = <JWS_TOKEN_VALUE> "
pass JWS_TOKEN_VALUE in the http header 'x-gl-token-external'
pass JWE_TOKEN_VALUE in the http body
```

Rest API
```
"call respective rest API for with header and body information"
End points:
UAT Environment : https://api.uat.payglocal.in
Production Environment: https://api.prod.payglocal.in

Alt ID API 
POST : /gl/v1/altId

Payment API 
POST : /gl/v1/payments/initiate

Compliance API 
POST :  /gcc/v1/compliance/check
```



