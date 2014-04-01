//
//  OpenIDConnectLibrary.h
//  OpenIDConnectLibrary
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface OpenIDConnectLibrary : NSObject

+(NSDictionary *)parseIDToken:(NSString *)idToken forClient:(NSString *)client_id withNonce:(NSString *)nonce;
+(NSDictionary *)parseIDToken:(NSString *)idToken forClient:(NSString *)client_id withAccessToken:(NSString *)access_token withNonce:(NSString *)nonce;
+(NSDictionary *)parseIDToken:(NSString *)idToken forClient:(NSString *)client_id withAccessToken:(NSString *)access_token;
+(NSString *)getParsedHeaderForToken:(NSString *)token;
+(NSString *)getParsedPayloadForToken:(NSString *)token;

@end
