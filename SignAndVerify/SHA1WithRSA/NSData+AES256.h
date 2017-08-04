//
//  NSData+AES256.h
//  
//
//  Created by Yubin on 16/8/1.
//  Copyright © 2016年 X. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@interface NSData (AES256)

- (NSData *)aes256_encryptWithKey:(NSString *)key;
- (NSData *)aes256_decryptWithKey:(NSString *)key;

@end
