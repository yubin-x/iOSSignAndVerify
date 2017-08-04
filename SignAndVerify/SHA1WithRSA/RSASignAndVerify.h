//
//  RSASignAndVerify.h
//  
//
//  Created by Yubin on 2017/8/3.
//  Copyright © 2017年 X. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSASignAndVerify : NSObject

+ (NSString *)sign:(NSString *)content withPriKey:(NSString *)priKey;
+ (BOOL)verify:(NSString *)content signature:(NSString *)signature withPublivKey:(NSString *)publicKey;

@end
