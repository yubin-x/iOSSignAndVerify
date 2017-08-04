//
//  RSASignAndVerify.m
//  
//
//  Created by Yubin on 2017/8/3.
//  Copyright © 2017年 X. All rights reserved.
//

#import "RSASignAndVerify.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation RSASignAndVerify


//+ (NSString *)unwrapPublicKey:(NSString *)pubkey
//{
//    
//}
//
//+ (NSString *)unwrapPrivateKey:(NSString *)prikey
//{
//    
//}

+ (SecKeyRef)addPrivateKey:(NSString *)key{
    
    // This is a base64 encoded key. so, decode it.
    NSData *data = [[NSData alloc] initWithBase64EncodedString:key options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    if(!data){ return nil; }
    //a tag to read/write keychain storage
    NSString *tag = @"RSA_PRIVATE_KEY";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *privateKey = [[NSMutableDictionary alloc] init];
    [privateKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [privateKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)privateKey);
    
    // Add persistent version of the key to system keychain
    [privateKey setObject:data forKey:(__bridge id)kSecValueData];
    [privateKey setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)privateKey, &persistKey);
    if (persistKey != nil){ CFRelease(persistKey); }
    if ((status != noErr) && (status != errSecDuplicateItem)) { return nil; }
    
    [privateKey removeObjectForKey:(__bridge id)kSecValueData];
    [privateKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}

+ (SecKeyRef)addPublicKey:(NSString *)pubKey
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:pubKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSA_PUBLIC_KEY";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    // Add persistent version of the key to system keychain
    [publicKey setObject:data forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    
    if ((status != noErr) && (status != errSecDuplicateItem)) { return nil; }
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}

// digest message with sha1
+ (NSData *)sha1:(NSString *)str
{
    const void *data = [str cStringUsingEncoding:NSUTF8StringEncoding];
    CC_LONG len = (CC_LONG)strlen(data);
    uint8_t * md = malloc( CC_SHA1_DIGEST_LENGTH * sizeof(uint8_t) );;
    CC_SHA1(data, len, md);
    return [NSData dataWithBytes:md length:CC_SHA1_DIGEST_LENGTH];
}
// Using the RSA private key to sign the specified message
+ (NSString *)sign:(NSString *)content withPriKey:(NSString *)priKey
{
    SecKeyRef privateKeyRef = [self addPrivateKey:priKey];
    if (!privateKeyRef) { NSLog(@"添加私钥失败"); return  nil; }
    NSData *sha1Data = [self sha1:content];
    unsigned char *sig = (unsigned char *)malloc(256);
    size_t sig_len;
    OSStatus status = SecKeyRawSign(privateKeyRef, kSecPaddingPKCS1SHA1, [sha1Data bytes], CC_SHA1_DIGEST_LENGTH, sig, &sig_len);
    
    if (status != noErr) { NSLog(@"加签失败:%d",status); return nil; }
    
    NSData *outData = [NSData dataWithBytes:sig length:sig_len];
    return [outData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}
// verify Signature
+ (BOOL)verify:(NSString *)content signature:(NSString *)signature withPublivKey:(NSString *)publicKey {
    
    SecKeyRef publicKeyRef = [self addPublicKey:publicKey];
    if (!publicKeyRef) { NSLog(@"添加公钥失败"); return NO; }
    NSData *originData = [self sha1:content];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:signature options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!originData || !signatureData) { return NO; }
    OSStatus status =  SecKeyRawVerify(publicKeyRef, kSecPaddingPKCS1SHA1, [originData bytes], originData.length, [signatureData bytes], signatureData.length);
    
    if (status ==noErr) { return  YES; }
    else{ NSLog(@"验签失败:%d",status); return NO; }
}

@end
