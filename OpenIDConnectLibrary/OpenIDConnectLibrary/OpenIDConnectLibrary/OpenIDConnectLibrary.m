//
//  OpenIDConnectLibrary.m
//  OpenIDConnectLibrary
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "OpenIDConnectLibrary.h"
#import "JSONWebToken.h"
#import "OIDCHelper.h"


@implementation OpenIDConnectLibrary

+(NSDictionary *)parseIDToken:(NSString *)idToken forClient:(NSString *)client_id withNonce:(NSString *)nonce
{
    // Used for the Implicit grant type without an access token
    
    JSONWebToken *jwt = [[JSONWebToken alloc] initWithToken:idToken ofType:@"id_token"];
    if ([OIDCHelper validateIDToken:jwt ForClientId:client_id WithNonce:nonce])
    {
        return [jwt parsed_payload];
    } else
    {
        return nil;
    }
}

+(NSDictionary *)parseIDToken:(NSString *)idToken forClient:(NSString *)client_id withAccessToken:(NSString *)access_token withNonce:(NSString *)nonce
{
    // Used for the Implicit grant type with an access token
    
    JSONWebToken *jwt = [[JSONWebToken alloc] initWithToken:idToken ofType:@"id_token"];
    if ([OIDCHelper validateIDToken:jwt ForClientId:client_id WithAccessToken:access_token AndNonce:nonce])
    {
        return [jwt parsed_payload];
    } else
    {
        return nil;
    }
}

+(NSDictionary *)parseIDToken:(NSString *)idToken forClient:(NSString *)client_id withAccessToken:(NSString *)access_token
{
    // Used for the AuthZ grant type with an access token
    
    JSONWebToken *jwt = [[JSONWebToken alloc] initWithToken:idToken ofType:@"id_token"];
    if ([OIDCHelper validateIDToken:jwt ForClientId:client_id WithAccessToken:access_token])
    {
        return [jwt parsed_payload];
    } else
    {
        return nil;
    }
}

+(BOOL)validateIDToken:(NSString *)idToken forClient:(NSString *)client_id withNonce:(NSString *)nonce
{
    return YES;
}

+(NSString *)getParsedHeaderForToken:(NSString *)token
{
    JSONWebToken *jwt = [[JSONWebToken alloc] initWithToken:token ofType:@"any"];
    return [OIDCHelper jsonPrettyPrint:[jwt parsed_header]];
}

+(NSString *)getParsedPayloadForToken:(NSString *)token
{
    JSONWebToken *jwt = [[JSONWebToken alloc] initWithToken:token ofType:@"any"];
    return [OIDCHelper jsonPrettyPrint:[jwt parsed_payload]];
}

@end
