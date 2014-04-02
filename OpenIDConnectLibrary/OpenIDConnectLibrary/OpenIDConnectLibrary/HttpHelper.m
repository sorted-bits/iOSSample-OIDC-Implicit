//
//  HttpHelper.m
//  OpenIDConnectLibrary
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "HttpHelper.h"
#import "HttpResponse.h"
#import "HttpIgnoreSSLErrors.h"


@implementation HttpHelper

NSTimer *HttpTimeout;
NSURLConnection *c;

+(NSData *) base64DecodeString:(NSString *)base64EncodedString
{
    NSString *cleanBase64EncodedString = [[[base64EncodedString stringByReplacingOccurrencesOfString:@"\n" withString:@""] stringByReplacingOccurrencesOfString:@"-" withString:@"+"] stringByReplacingOccurrencesOfString:@"_" withString:@"/"];

    NSInteger numEqualsNeeded = 4 - ([cleanBase64EncodedString length] % 4);
    if (numEqualsNeeded == 4) { numEqualsNeeded = 0; }
    NSString *padding = [@"" stringByPaddingToLength:numEqualsNeeded withString:@"=" startingAtIndex:0];
    NSString *base64EncodedStringPadded = [NSString stringWithFormat:@"%@%@", cleanBase64EncodedString, padding];
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:base64EncodedStringPadded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    return decodedData;
}

+ (HttpResponse *) postToUrl:(NSString *)url withPostData:(NSString *)postData
{
    NSLog(@"Contacting URL: %@", url);
    NSLog(@"Request body (POST data): %@", postData);
    
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] init];
    [request setURL:[NSURL URLWithString:[NSString stringWithFormat:@"%@", url]]];
    [request setHTTPMethod:@"POST"];
    [request setHTTPBody:[postData dataUsingEncoding:NSUTF8StringEncoding]];
    [request setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
    [request setTimeoutInterval:10];
    
    // *** Set a 10 second timeout for the Http call
    HttpTimeout = [NSTimer scheduledTimerWithTimeInterval:10 target:self selector:@selector(timeoutExpired:) userInfo:nil repeats:NO];
    
    // *** Ignore SSL Certificate errors that are likely in a test environment.  DO NOT USE THIS IN PRODUCTION!
    HttpIgnoreSSLErrors *ignoreSSL = [[HttpIgnoreSSLErrors alloc] init];
    c = [[NSURLConnection alloc] initWithRequest:request delegate:ignoreSSL startImmediately:NO];
    [c setDelegateQueue:[[NSOperationQueue alloc] init]];
    [c start];

    HttpResponse *httpResponse = [[HttpResponse alloc] init];
    [httpResponse setResponseData:[ignoreSSL getData]];
    [httpResponse setResponseCode:[ignoreSSL responseCode]];
    
    return httpResponse;
}

+(HttpResponse *)getUrl:(NSString *)url withAuthZHeader:(NSString *)authZHeader
{
    NSLog(@"Contacting URL: %@", url);
    
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] init];
    [request setURL:[NSURL URLWithString:[NSString stringWithFormat:@"%@", url]]];
    if (authZHeader != nil) {
        NSLog(@"Using Authorization header: %@", authZHeader);
        [request addValue:authZHeader forHTTPHeaderField:@"Authorization"];
    }
    [request setHTTPMethod:@"GET"];
    [request setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
    [request setTimeoutInterval:10];
    
    // *** Set a 10 second timeout for the Http call
    HttpTimeout = [NSTimer scheduledTimerWithTimeInterval:10 target:self selector:@selector(timeoutExpired:) userInfo:nil repeats:NO];
    
    // *** Ignore SSL Certificate errors that are likely in a test environment.  DO NOT USE THIS IN PRODUCTION!
    HttpIgnoreSSLErrors *ignoreSSL = [[HttpIgnoreSSLErrors alloc] init];
    c = [[NSURLConnection alloc] initWithRequest:request delegate:ignoreSSL startImmediately:NO];
    [c setDelegateQueue:[[NSOperationQueue alloc] init]];
    [c start];
    
    HttpResponse *httpResponse = [[HttpResponse alloc] init];
    [httpResponse setResponseData:[ignoreSSL getData]];
    [httpResponse setResponseCode:[ignoreSSL responseCode]];
    
    return httpResponse;
}

+(void)timeoutExpired:(NSTimer *)timer
{
    if (c != nil) {
        [c cancel];
    }
}

@end
