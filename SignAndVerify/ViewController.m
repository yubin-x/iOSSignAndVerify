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

- (void)testSignAndVerifyLocalData
{
    NSString *prikey = @"MIICXAIBAAKBgQDDexXjLoCmBU3TqiiAmHqkX0AMxLaPIz9U2nExHMQLDjQTZmpK\nsJTClwec/m+NMapG1lujQnoinp/jKtXCUPWWYGJItxqXAM0sT91QtyotCYynwHHt\nwhsYQedW9/KaN6eCMnrZoDd8oTKJQszjpFpHxV4GOKqkFRL2UBN6a4n+WwIDAQAB\nAoGAB0HNiTaTvhYaUo5RnJyMiQekOBUhdeToF/1YEGux93sagdHehlFR5Ht44+Iq\nQAKlAKY6lrAEGr7qzqMrdmBNDaxiPfhKU/NqLwNDP5sbZaA40+MD2nyuCsfPAD4m\npRrd9Ut4KXUeubQn5B5y4i74bXTKkQvpueoLenE5HKn3DyECQQD75vjg3p1Lbu9E\nBngPIS8bysmafdY8kgYxyjA088HqEEh4k/oyGg1Cz8kDE/77+kf23ksasVf8cuWL\naLN1Z8dRAkEAxqkmiN3HOuDFeDAxG+HF4vomIp0gnqCXZGsCPAKbHdBytdr9mTxj\nYtj9PZ4ZzyMIM4H1JeOj36j1O2bsGJHX6wJAGgOQUCitNc0PCIdifq1+n/AhQcMd\nDMRHv3yR3eYOcI2d7lXZ0LLAC9ZJe/fkrUD7jZMHToph+8Ah1HPLlKRTAQJACWvU\nLAF4hU5LjxuZ+JyIae87B8Ez3tH23AhHHtlwycUs63rrM+0tOW7Y86cfyjb7GJY9\nLgLRrrWwi5Sh9bhU6QJBAJbWhJknnygWs8jQTINCgOhpCFmIKMJCsuMd6Zuh0PCX\n8Fu8LIXQEbNGck4lGheyuz7ppjCwCQ8408jhNNMZ5eM=";
    
    NSString *pubkey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDexXjLoCmBU3TqiiAmHqkX0AM\nxLaPIz9U2nExHMQLDjQTZmpKsJTClwec/m+NMapG1lujQnoinp/jKtXCUPWWYGJI\ntxqXAM0sT91QtyotCYynwHHtwhsYQedW9/KaN6eCMnrZoDd8oTKJQszjpFpHxV4G\nOKqkFRL2UBN6a4n+WwIDAQAB";
    
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
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    
}


@end
