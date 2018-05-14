# iOSSignAndVerify

详细介绍：[iOS RSA加签和验签（SHA1WithRSA）](http://www.jianshu.com/p/d6aa4ca4c243)

#### Usage

~~~
//sign
NSString *signSHA384 = [RSASignAndVerify sign:plainText withPriKey:prikey withShaX:kSecPaddingPKCS1SHA384];

//verfy
success = [RSASignAndVerify verify:plainText signature:signSHA384 publivKey:pubkey withShaX:kSecPaddingPKCS1SHA384];
~~~
