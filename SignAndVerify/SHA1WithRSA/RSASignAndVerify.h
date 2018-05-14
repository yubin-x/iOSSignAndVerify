//
//  RSASignAndVerify.h
//  
//
//  Created by Yubin on 2017/8/3.
//  Copyright © 2017年 X. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSASignAndVerify : NSObject

//SHA1
+ (NSString *)sign:(NSString *)content withPriKey:(NSString *)priKey;

+ (BOOL)verify:(NSString *)content signature:(NSString *)signature withPublivKey:(NSString *)publicKey;

//SHA1、SHA224、SHA256、SHA384、SHA512
+ (NSString *)sign:(NSString *)content withPriKey:(NSString *)priKey withShaX:(SecPadding)type;

+ (BOOL)verify:(NSString *)content signature:(NSString *)signature publivKey:(NSString *)publicKey withShaX:(SecPadding)type;

@end
