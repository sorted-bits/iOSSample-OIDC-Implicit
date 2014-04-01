//
//  OIDCHelper.h
//  OAuthPlayground
//
//  Created by Paul Meyer on 10/17/13.
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "JSONWebToken.h"

@interface OIDCHelper : NSObject

+(NSString *)jsonPrettyPrint:(NSDictionary *)jsonDictionary;
+(NSString *)jsonPrettyPrint:(NSString *)jsonString base64Encoded:(BOOL)base64Encoded;
+(SecKeyRef)getIDTokenSigningKeyFromIssuer:(NSString *)issuer andKID:(NSString *)kid;
+(SecKeyRef)getAccessTokenSigningKeyFromIssuer:(NSString *)issuer andKID:(NSString *)kid;
+(BOOL)validateSignatureForToken:(JSONWebToken *)token;
+(BOOL)validateAccessToken:(JSONWebToken *)accessToken ForClientId:(NSString *)client_id;
+(BOOL)validateIDToken:(JSONWebToken *)idToken ForClientId:(NSString *)client_id;
+(BOOL)validateIDToken:(JSONWebToken *)idToken ForClientId:(NSString *)client_id WithAccessToken:(NSString *)access_token;
+(BOOL)validateIDToken:(JSONWebToken *)idToken ForClientId:(NSString *)client_id WithNonce:(NSString *)nonce;
+(BOOL)validateIDToken:(JSONWebToken *)idToken ForClientId:(NSString *)client_id WithAccessToken:(NSString *)access_token AndNonce:(NSString *)nonce;

@end
