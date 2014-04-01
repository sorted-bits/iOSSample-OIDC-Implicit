//
//  SampleAppCurrentSession.m
//  SampleApp
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "SampleAppCurrentSession.h"
#import "OpenIDConnectLibrary.h"

@implementation SampleAppCurrentSession

@synthesize issuer = _issuer;
@synthesize client_id = _client_id;
@synthesize nonce = _nonce;

@synthesize OIDCImplicitProfile = _OIDCImplicitProfile;

NSDictionary *_allAttributes;

+(SampleAppCurrentSession *)session
{
    static SampleAppCurrentSession *sess;
    
    if(sess == nil)
    {
        sess = [[SampleAppCurrentSession alloc] init];
    }
    
    return sess;
}

-(id)init
{
    self = [super init];
    
    if (self)
    {
    }
    
    return self;
}

-(NSArray *)getAllAttributes
{
    return [_allAttributes allKeys];
}

-(NSString *)getValueForAttribute:(NSString *)attribute
{
    return [_allAttributes valueForKey:attribute];
}

-(void)createSession
{
    if(![self inErrorState])
    {
        NSString *id_token = [_OIDCImplicitProfile getOAuthParameter:kOAuth2ParamIdToken];
        
        _allAttributes = [OpenIDConnectLibrary parseIDToken:id_token forClient:_client_id withNonce:_nonce];
        NSLog(@"Created Session: %@", _allAttributes);
    }
}

-(BOOL)isAuthenticated
{
    if([_allAttributes count] > 0)
    {
        return YES;
    }
    else {
        return NO;
    }
}

-(void)logout
{
    _allAttributes = nil;
}

-(BOOL)inErrorState
{
    if([_OIDCImplicitProfile getOAuthParameter:kOAuth2ParamError] != nil)
    {
        return YES;
    }
    
    return NO;
}

-(NSString *)getLastError
{
    if ([self inErrorState]) {
        return [_OIDCImplicitProfile getOAuthParameter:kOAuth2ParamErrorDescription];
    } else {
        return @"";
    }
}

@end
