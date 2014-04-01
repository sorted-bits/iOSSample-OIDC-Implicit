//
//  SampleAppCurrentSession.h
//  SampleApp
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OAuth2Client.h"

@interface SampleAppCurrentSession : NSObject
{
    NSString *issuer;
    NSString *client_id;
    NSString *nonce;
    
    OAuth2Client *OIDCImplicitProfile;
}

@property (nonatomic, retain) NSString *issuer;
@property (nonatomic, retain) NSString *client_id;
@property (nonatomic, retain) NSString *nonce;

@property (nonatomic, retain) OAuth2Client *OIDCImplicitProfile;

+ (SampleAppCurrentSession *)session;
- (void)logout;
- (NSArray *)getAllAttributes;
- (NSString *)getValueForAttribute:(NSString *)attribute;
- (BOOL)isAuthenticated;
- (BOOL)inErrorState;
- (void)createSession;
- (NSString *)getLastError;

@end
