//
//  NSString+AES256.m
//  
//
//  Created by Yubin on 16/8/1.
//  Copyright © 2016年 X. All rights reserved.
//

#import "NSString+AES256.h"

@implementation NSString (AES256)

- (NSString *) aes256_encryptWithKey:(NSString *)key
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    //对数据进行加密
    NSData *result = [data aes256_encryptWithKey:key];
    NSData *base64Data = [result base64EncodedDataWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSString *base64Str = [[NSString alloc] initWithData:base64Data encoding:NSUTF8StringEncoding];
    return base64Str;
}

- (NSString *) aes256_decryptWithKey:(NSString *)key
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:self options:NSDataBase64DecodingIgnoreUnknownCharacters];
    //对数据进行解密
    NSData* result = [data aes256_decryptWithKey:key];
    if (result && result.length > 0) {
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    }
    return nil;
}

@end
