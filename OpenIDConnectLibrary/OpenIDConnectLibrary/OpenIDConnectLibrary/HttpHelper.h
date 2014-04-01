//
//  HttpHelper.h
//  OpenIDConnectLibrary
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "HttpResponse.h"

@interface HttpHelper : NSObject

+(NSData *)base64DecodeString:(NSString * )base64EncodedString;
+(HttpResponse *)postToUrl:(NSString *)url withPostData:(NSString *)postData;
+(HttpResponse *)getUrl:(NSString *)url withAuthZHeader:(NSString *)authZHeader;

@end
