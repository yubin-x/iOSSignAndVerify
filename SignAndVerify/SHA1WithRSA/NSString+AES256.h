//
//  NSString+AES256.h
//  
//
//  Created by Yubin on 16/8/1.
//  Copyright © 2016年 X. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#import "NSData+AES256.h"

@interface NSString(AES256)

- (NSString *) aes256_encryptWithKey:(NSString *)key;
- (NSString *) aes256_decryptWithKey:(NSString *)key;

@end
