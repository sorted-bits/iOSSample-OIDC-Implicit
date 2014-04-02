//
//  OIDCHelper.m
//  OAuthPlayground
//
//  Created by Paul Meyer on 10/17/13.
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import "OIDCHelper.h"
#import "JSONWebToken.h"
#import "CertHelper.h"
#import "SHA.h"
#import "HMAC.h"
#import "RSAPKCS1_5.h"

#import "HttpHelper.h"
#import "HttpResponse.h"

#import <Security/Security.h>


@implementation OIDCHelper

-(id) init
{
    self = [super init];
    
    if (self)
    {
    }
    
    return self;
}

+(NSString *) jsonPrettyPrint:(NSString *)jsonString base64Encoded:(BOOL)base64Encoded
{
    NSData *jsonData = nil;
    
    if (base64Encoded) {
        jsonData = [HttpHelper base64DecodeString:jsonString];
    } else {
        jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    }
    
    NSError *error = nil;
    NSDictionary *jsonDictionary = [NSJSONSerialization JSONObjectWithData:jsonData options:kNilOptions error:&error];

    NSMutableString *returnString = [[NSMutableString alloc] init];
    
    for (NSString *k in jsonDictionary) {
        
        if ([k isEqualToString:@"exp"] || [k isEqualToString:@"iat"] ) {
            [returnString appendFormat:@"%@: %@ (%@)\r\n", k, [jsonDictionary valueForKey:k], [NSDate dateWithTimeIntervalSince1970:[[jsonDictionary valueForKey:k] doubleValue]]];
        } else {
            [returnString appendFormat:@"%@: %@\r\n", k, [jsonDictionary valueForKey:k]];
        }
    }
    
    return returnString;
}

+(NSString *) jsonPrettyPrint:(NSDictionary *)jsonDictionary
{
    NSMutableString *returnString = [[NSMutableString alloc] init];
    
    
    for (NSString *k in jsonDictionary) {
        
        if ([k isEqualToString:@"exp"] || [k isEqualToString:@"iat"] ) {
            [returnString appendFormat:@"%@: %@ (%@)\r\n", k, [jsonDictionary valueForKey:k], [NSDate dateWithTimeIntervalSince1970:[[jsonDictionary valueForKey:k] doubleValue]]];
        } else {
            [returnString appendFormat:@"%@: %@\r\n", k, [jsonDictionary valueForKey:k]];
        }
    }
    
    return returnString;
}

+(SecKeyRef) getIDTokenSigningKeyFromIssuer:(NSString *)issuer andKID:(NSString *)kid
{
//    SecKeyRef returnKey = [CertHelper getPublicCertFromKeyChainByIssuer:issuer andKID:kid];
    SecKeyRef returnKey = nil;
    
    if (returnKey == nil) {
        NSString *wellKnownUrl = [NSString stringWithFormat:@"%@/.well-known/openid-configuration", issuer];
        NSLog(@"Retrieving JWKS url from .well-known url: %@", wellKnownUrl);
        
        HttpResponse *response = [HttpHelper getUrl:wellKnownUrl withAuthZHeader:nil];
        
        if(response.responseCode == 200) {
            NSError *error = nil;
            NSDictionary *jsonWellKnown = [NSJSONSerialization JSONObjectWithData:response.responseData options:kNilOptions error:&error];
            
            NSLog(@"Retrieving JWKS from JWKS url: %@", [jsonWellKnown objectForKey:@"jwks_uri"]);

            NSError *jwks_error = nil;
            HttpResponse *jwks = [HttpHelper getUrl:[jsonWellKnown objectForKey:@"jwks_uri"] withAuthZHeader:nil];
            NSDictionary *jsonJWKS = [NSJSONSerialization JSONObjectWithData:jwks.responseData options:kNilOptions error:&jwks_error];
            
            NSArray *keys = [jsonJWKS objectForKey:@"keys"];
            
            NSString *certModulus;
            NSString *certExponent;
            
            for(NSDictionary *obj in keys) {
                if ([[obj objectForKey:@"kid"] isEqualToString:kid]) {
                    certModulus = [obj objectForKey:@"n"];
                    certExponent = [obj objectForKey:@"e"];
                    NSLog(@"Found key in JWKS: %@", obj);
                }
            }
            
            returnKey = [CertHelper getPublicCertUsingModulus:[HttpHelper base64DecodeString:certModulus] exponent:[HttpHelper base64DecodeString:certExponent]];
            [CertHelper storePublicCertInKeyChain:returnKey issuer:issuer kid:kid];

        } else {
            NSLog(@"Failed to retrieve JWKS");
            return nil;
        }
    }

    return returnKey;
}


+(SecKeyRef) getAccessTokenSigningKeyFromIssuer:(NSString *)issuer andKID:(NSString *)kid
{
    SecKeyRef returnKey = [CertHelper getPublicCertFromKeyChainByIssuer:issuer andKID:kid];
    
    if (returnKey == nil) {
        NSString *certUrl = [NSString stringWithFormat:@"%@/ext/oauth/x509/kid?v=%@", issuer, kid];
        NSLog(@"Retrieving Access Token signing cert from: %@", certUrl);
        
        HttpResponse *response = [HttpHelper getUrl:certUrl withAuthZHeader:nil];
        
        if (response.responseCode == 200) {
            NSString *publicCert = [[NSString alloc] initWithData:response.responseData encoding:NSUTF8StringEncoding];
            NSString *formattedCert = [[publicCert stringByReplacingOccurrencesOfString:@"-----BEGIN CERTIFICATE-----\n" withString:@""] stringByReplacingOccurrencesOfString:@"\n-----END CERTIFICATE-----\n" withString:@""];

            NSLog(@"Retrieved certificate: %@", formattedCert);

            returnKey = [CertHelper getPublicCertFromX509Data:[HttpHelper base64DecodeString:formattedCert]];
            [CertHelper storePublicCertInKeyChain:returnKey issuer:issuer kid:kid];
            
        } else {
            NSLog(@"Error retrieving certificate");
            return nil;
        }
    }

    return returnKey;
}


// Token Validation

//If the Client has provided an id_token_encrypted_response_alg parameter during Registration, decrypt the ID Token using the key pair specified during Registration.

//If the id_token is received via direct communication between the Client and the Token Endpoint, the TLS server validation MAY be used to validate the issuer in place of checking the token signature. The Client MUST validate the signature of all other ID Tokens according to JWS [JWS] using the algorithm specified in the alg parameter of the JWT header.

//If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate. The meaning and processing of acr Claim Values is out of scope for this specification.


//The alg value SHOULD be the default of RS256 or the algorithm sent by the Client in the id_token_signed_response_alg parameter during Registration.
//If the alg parameter of the JWT header is a MAC based algorithm such as HS256, HS384, or HS512, the octets of the UTF-8 representation of the client_secret corresponding to the client_id contained in the aud (audience) Claim are used as the key to validate the signature. Multiple audiences are not supported for MAC based algorithms.
//For other Signing algorithms, the Client MUST use the signing key provided in Discovery by the Issuer. The issuer MUST exactly match the value of the iss (issuer) Claim.

//The current time MUST be less than the value of the exp Claim.

//The iat Claim can be used to reject tokens that were issued too far away from the current time, limiting the amount of time that nonces need to be stored to prevent attacks. The acceptable range is Client specific.

//If a nonce value was sent in the Authorization Request, a nonce Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the Authorization Request. The Client SHOULD check the nonce value for replay attacks. The precise method for detecting replay attacks is Client specific.

//If the auth_time Claim was requested, either through a specific request for this Claim or by using the max_age parameter, the Client SHOULD check the auth_time Claim value and request re-authentication if it determines too much time has elapsed since the last End-User authentication.


+(BOOL) validateAccessToken:(JSONWebToken *)accessToken ForClientId:(NSString *)client_id
{
    BOOL isValidToken = YES;
    
    NSLog(@"---[ Validating JWT OAuth2 access token ]------");
    
    // client_id SHOULD match the client_id that requested the token
    NSLog(@"Checking client_id");

    if ([self validateClientIdForToken:accessToken ClientId:client_id])
    {
        NSLog(@"YES: client_id is valid");
    } else {
        NSLog(@"NO : client_id does not match");
        isValidToken = NO;
    }
    
    // token MUST not have expired
    NSLog(@"Checking token expiry");

    if ([self validateTimeClaimForToken:accessToken Claim:@"exp" skewSeconds:0])
    {
        NSLog(@"YES: Token is valid");
    } else {
        NSLog(@"NO : Token has expired");
        isValidToken = NO;
    }

    NSLog(@"Validating Signature");

    if ([self validateSignatureForToken:accessToken]) {
        NSLog(@"YES: Signature is correct");
    } else {
        NSLog(@"NO : Invalid signature");
        [[accessToken validation_comments] addObject:@"Invalid signature"];
        isValidToken = NO;
    }
    
    NSLog(@"---[ Verification Complete ]------");
    return isValidToken;
}

+(BOOL) validateIDToken:(JSONWebToken *)idToken ForClientId:(NSString *)client_id
{
    return [self validateIDToken:idToken ForClientId:client_id WithAccessToken:nil AndNonce:nil];
}

+(BOOL) validateIDToken:(JSONWebToken *)idToken ForClientId:(NSString *)client_id WithAccessToken:(NSString *)access_token
{
    return [self validateIDToken:idToken ForClientId:client_id WithAccessToken:access_token AndNonce:nil];
}

+(BOOL) validateIDToken:(JSONWebToken *)idToken ForClientId:(NSString *)client_id WithNonce:(NSString *)nonce
{
    return [self validateIDToken:idToken ForClientId:client_id WithAccessToken:nil AndNonce:nonce];
}

+(BOOL) validateIDToken:(JSONWebToken *)idToken ForClientId:(NSString *)client_id WithAccessToken:(NSString *)access_token AndNonce:(NSString *)nonce
{
    BOOL isValidToken = YES;
    
    NSLog(@"---[ Validating JWT ID token ]------");
    // check it has a sub
    // check is has an issuer

    // validate the audience
    NSLog(@"Checking audience");

    if ([self validateAudienceForToken:idToken Audience:client_id])
    {
        NSLog(@"YES: audience is valid");
    } else {
        NSLog(@"NO : audience does not match");
        isValidToken = NO;
    }
    
    // token MUST not have expired
    NSLog(@"Checking expiry");

    if ([self validateTimeClaimForToken:idToken Claim:@"exp" skewSeconds:0])
    {
        NSLog(@"YES: Token is valid");
    } else {
        NSLog(@"NO : Token has expired");
        isValidToken = NO;
    }
    
    // at_hash need only be present for an implicit grant type, authz code grant type is OPTIONAL
    NSLog(@"Checking at_hash");
    if (access_token != nil) {

        if([self validateAt_HashForToken:idToken AccessToken:access_token])
        {
            NSLog(@"YES: at_hash is valid");
        } else {
            NSLog(@"NO : at_hash does not match access token");
            isValidToken = NO;
        }

    }

// The Client MUST validate the signature of the ID Token according to JWS [JWS] using the algorithm specified in the alg parameter of the JWT header.
// The alg value SHOULD be RS256. Validation of tokens using other signing algorithms is described in the OpenID Connect Core 1.0 [OpenID.Core] specification.
// The Client MUST use the signing key provided in Discovery by the Issuer. The Issuer MUST exactly match the value of the iss (issuer) Claim.
    NSLog(@"Validating Signature");
    
    if ([self validateSignatureForToken:idToken]) {
        NSLog(@"YES: Signature is correct");
    } else {
        NSLog(@"NO : Invalid signature");
        [[idToken validation_comments] addObject:@"Invalid signature"];
        isValidToken = NO;
    }
    
// The value of the nonce Claim MUST be checked to verify that it is the same value as the one that was sent in the Authorization Request. The Client SHOULD check the nonce value for replay attacks. The precise method for detecting replay attacks is Client specific.

    if (nonce != nil)
    {
        NSLog(@"Checking nonce");
        if ([self validateNonceForToken:idToken Nonce:nonce])
        {
            NSLog(@"YES: nonce is valid");
        } else {
            NSLog(@"NO : nonce does not match request");
            isValidToken = NO;
        }
    }
    
// If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate. The meaning and processing of acr Claim Values is out of scope for this specification.
// When a max_age request is made, the Client SHOULD check the auth_time Claim value and request re-authentication if it determines too much time has elapsed since the last End-User authentication.

    NSLog(@"---[ Verification Complete ]------");
    return isValidToken;
}

// Token Validation

+(BOOL) checkValue:(NSString *)expectedValue forKey:(NSString *)key inDictionary:(NSDictionary *)dictionary okayToNotExist:(BOOL)okayToNotExist
{
    BOOL isValidValue = NO;
    
    NSString *valueToCheck = [dictionary objectForKey:key];
    
    if ([valueToCheck length] != 0) {
        if ([valueToCheck isEqualToString:expectedValue]) {
            isValidValue = YES;
        } else {
            isValidValue = NO;
        }
    } else {
        return okayToNotExist;
    }
    
    return isValidValue;
}

+(BOOL)validateAudienceForToken:(JSONWebToken *)token Audience:(NSString *)expectedAudience
{
    BOOL isValid = NO;
    // Rules according to OpenID Connect Core (draft 14)
    //The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
    // If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
    // If an azp (authorized party) Claim is present, the Client SHOULD verify and that its client_id is the Claim value.
    
    if ([[token getValueFromPayload:@"aud"] isKindOfClass:[NSArray class]])
    {
        // we have multiple audiences
        for (NSString *thisAudience in [token getValueFromPayload:@"aud"])
        {
            if ([thisAudience isEqualToString:expectedAudience])
            {
                // audience is there and matches
                isValid = YES;
            }
        }
        
        if ([self checkValue:expectedAudience forKey:@"azp" inDictionary:[token getPayloadAsDictionary] okayToNotExist:NO]) {
            // audience is there and matches
            isValid = YES;
        } else {
            [[token validation_comments] addObject:@"Invalid audience (multiple audiences, azp check failed)"];
        }
        
    } else {
        if ([self checkValue:expectedAudience forKey:@"aud" inDictionary:[token getPayloadAsDictionary] okayToNotExist:NO]) {
            // audience is there and matches
            isValid = YES;
        } else {
            [[token validation_comments] addObject:@"Invalid audience"];
        }
    }
    
    return isValid;
}

+(BOOL)validateClientIdForToken:(JSONWebToken *)token ClientId:(NSString *)expectedClientId
{
    BOOL isValid = NO;
    
    // For an OAuth2 access token (JWT version) the client_id claim MUST match the client_id used to request the token
    
    if ([self checkValue:expectedClientId forKey:@"client_id" inDictionary:[token getPayloadAsDictionary] okayToNotExist:NO]) {
        // value is there and matches
        isValid = YES;
    } else {
        [[token validation_comments] addObject:@"Invalid client_id"];
    }
    
    return isValid;
}

+(BOOL)validateNonceForToken:(JSONWebToken *)token Nonce:(NSString *)expectedNonce
{
    BOOL isValid = NO;
    
    // For an id_token received via an implicit grant type, the nonce MUST match the value in the initial request
    
    if ([self checkValue:expectedNonce forKey:@"nonce" inDictionary:[token getPayloadAsDictionary] okayToNotExist:NO]) {
        // value is there and matches
        isValid = YES;
    } else {
        [[token validation_comments] addObject:@"Invalid nonce"];
    }
    
    return isValid;
}

+(BOOL)validateTimeClaimForToken:(JSONWebToken *)token Claim:(NSString *)claimName skewSeconds:(double)skew
{
    BOOL isValid = NO;
    
    NSDate *claimTimestamp = [NSDate dateWithTimeIntervalSince1970:[[token getValueFromPayload:claimName] doubleValue]];
    NSDate *nowPlusSkew = [[NSDate date] dateByAddingTimeInterval:skew];
    
    if ([claimTimestamp compare:nowPlusSkew] == NSOrderedDescending) {
        // value is before nowPlusSkew - so is in range
        isValid = YES;
    } else {
        [[token validation_comments] addObject:[NSString stringWithFormat:@"%@ not within range", claimName]];
    }
    return isValid;
}

+(BOOL)validateAt_HashForToken:(JSONWebToken *)token AccessToken:(NSString *)access_token
{
    BOOL isValid = NO;
    
    //at_hash - REQUIRED. Access Token hash value. If the ID Token is issued with an access_token in an implicit flow, this is REQUIRED, which is the case for this subset of OpenID Connect. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII    representation of the access_token value, where the hash algorithm used is the hash algorithm used in the alg parameter of the ID Token's JWS [JWS] header. For instance, if the alg is RS256, hash the access_token value with SHA-256, then take the left-most 128 bits and base64url encode them. The at_hash value is a case sensitive string.
    
    NSString *at_hash_value = [token getValueFromPayload:@"at_hash"];
    
    if (at_hash_value != nil)
    {
        NSData *at_hash = [HttpHelper base64DecodeString:at_hash_value];
        NSData *left_most_access_token = [[NSData alloc] init];
        
        if ([[token signing_alg] isEqualToString:@"None"])
        {
            // What do we do here?
            NSLog(@"The signing algorithm is None.  What size hash?");
        } else {
            NSInteger SHA_Digest_Length = [[[token signing_alg] substringFromIndex:2] integerValue];
            SHA *access_token_sha_hash = [[SHA alloc] initWithData:[access_token dataUsingEncoding:NSUTF8StringEncoding] andDigestLength:SHA_Digest_Length];
            NSMutableData *accessToken_hash = [[NSMutableData alloc] initWithData:[access_token_sha_hash getHashBytes]];
            left_most_access_token = [accessToken_hash subdataWithRange:NSMakeRange(0, 16)];
        }
        
        if ([at_hash isEqualToData:left_most_access_token]) {
            isValid = YES;
        } else {
            [[token validation_comments] addObject:@"Invalid at_hash - Does not match OAuth2 access token"];
        }
    } else {
        NSLog(@"at_hash not present - only required for implicit");
        isValid = YES;
    }
    
    return isValid;
}

+(BOOL) validateSignatureForToken:(JSONWebToken *)token
{
    return [self validateSignatureForToken:token withSymmetricKey:nil];
}

+(BOOL) validateSignatureForToken:(JSONWebToken *)token withSymmetricKey:(NSString *)symmetricKey
{
    // Handle the appropriate algorithm
    // Symmetric
    // HS 256, 384, 512 HMAC using SHA-xxx hash
    
    // Asymmetric
    // RS 256, 384, 512 RSASSA-PKCS-v1.5 using SHA-xxx hash
    // ES 256, 384, 512 ECDSA using P-xxx curve and SHA-xxx hash
    // PS 256, 384, 512 RSASSA-PSS using xxx hash and MGF1 mask generation
    
    // None
    // NONE
    
    if ([[token.signing_alg substringToIndex:2] isEqualToString:@"HS"]) { // Symmetric (HMAC w/SHA hash)
        
        return [token validateSignatureUsingSymmetricKey:symmetricKey];
        
    } else if([[token.signing_alg uppercaseString] isEqualToString:@"NONE"]) { // No signing
        
        return YES; // nothing to verify - so I guess the signature is good?

    } else if([[token.signing_alg substringToIndex:2] isEqualToString:@"RS"]) { // Asymmetric (RSA PKCS v1.5 w/ SHA hash)
        
        return [token validateSignature];
        
    } else {
        token.signature_comments = [NSString stringWithFormat:@"Unsupported algorithm: %@", token.signing_alg];
        return NO;
    }
    
    return NO;
}

@end
