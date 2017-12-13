//
//  ViewController.m
//  SignAndVerify
//
//  Created by Yubin on 2017/8/4.
//  Copyright © 2017年 X. All rights reserved.
//

#import "ViewController.h"
#import "RSASignAndVerify.h"
#import "NSString+AES256.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self testSignAndVerifyLocalData];
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self testSignAndVerifyLocalData];
}

- (void)testSignAndVerifyLocalData
{
    NSString *prikey = @"MIICXAIBAAKBgQDBO6ftQaxpW0YxFnNUELN/Hcpl3Rzpms4JMRToJoA/8WMyyz8GFsoqcWLcRoL8JjsisjzFVeaCMvPpjXZAGndY0cykllEN4/DZ5TGm6qZfuK2motIqLhMBudQN88nNEoSo1s/rxx86eK7OmLCgPhd3PctNAFD3dmgJRnv7L+53yQIDAQABAoGAGN4GhF/5Qi2+4L5U5TKpBujcjTNhbya+8Svh1uZths0XyQei+rOgHMouwM5KOQzqe1KYw4SEf6jy/tF3sFQ3m3tGudf+BkwfqKarAU4Z1sULnfIiEs4UVSpagdPZ7bQ7T2o4ZNec2B/USyPE1Zor867y27SgLOzEEfoxH0KhQwECQQDonl2hD7fnfhg6eCBDt/4aedZ+0KhwJR/XP5JRvsvXRh5eCFxuk7D+DgW0dK0BpByv/v/KU2pYAKd3t01Rg95RAkEA1KfWsIoNvZ5CefzZudZBHPI4Qpn5NT52iO0b8spOFMlEMA8KRtQHXTu9S2+w+YEzAauuqSeS6wQLHFFp8hHL+QJAdNqpOjGFNtsXHLgfrSUOlwpBgC8d jkh3+E9NF5d7Gsd0ldQparrynI06vG4oQrzIVHkK0f6ZW1/owLDqPFq8IQJAcs7iU5FU9chZb26ZRYFsyenjgeGK77n3WNlaO2wJV6OJksCr9a1HBIjaG74DN9EO7pn3xA8/fG5EaVdy8WO2UQJBAJXq1CbUQFuUPn5SOqU2EmQJ3ByXHXp4jXGpfWP0cshtLsasHVvgTvs9l248QknQCk8n949i9twu2L457JnGyAA=";
    
    NSString *pubkey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBO6ftQaxpW0YxFnNUELN/Hcpl3Rzpms4JMRToJoA/8WMyyz8GFsoqcWLcRoL8JjsisjzFVeaCMvPpjXZAGndY0cykllEN4/DZ5TGm6qZfuK2motIqLhMBudQN88nNEoSo1s/rxx86eK7OmLCgPhd3PctNAFD3dmgJRnv7L+53yQIDAQAB";
    
    NSString *aeskey = @"zxczxczxczxc";
    
    // 明文
    NSString *plainText = @"撸起袖子加油干";
    // AES加密后的密文
    NSString *cipherTextByAES = [plainText aes256_encryptWithKey:aeskey];
    // 签名
    NSString *signature = [RSASignAndVerify sign:cipherTextByAES withPriKey:prikey];
    // 验签
    BOOL success = [RSASignAndVerify verify:cipherTextByAES signature:signature withPublivKey:pubkey];
    
    NSLog(@"【明文】：%@",plainText);
    NSLog(@"【密文】：%@",cipherTextByAES);
    NSLog(@"【签名】：%@",signature);
    
    
    if (success) {
        NSLog(@"【验签成功】");
        NSString *decryptString = [cipherTextByAES aes256_decryptWithKey:aeskey];
        NSLog(@"【解密密文得到的明文】：%@",decryptString);
    }
    
    //support SHA1、SHA224、SHA256、 SHA384、SHA512
    NSString *signSHA384 = [RSASignAndVerify sign:plainText withPriKey:prikey withShaX:kSecPaddingPKCS1SHA384];
    success = [RSASignAndVerify verify:plainText signature:signSHA384 publivKey:pubkey withShaX:kSecPaddingPKCS1SHA384];
    NSLog(@"【SHA1】:%@", signSHA384);
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    
}


@end
