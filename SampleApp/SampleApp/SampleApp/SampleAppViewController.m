//
//  SampleAppViewController.m
//  SampleApp
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "SampleAppViewController.h"
#import "SampleAppCurrentSession.h"
#import "OpenIDConnectLibrary.h"

@interface SampleAppViewController ()

@end

@implementation SampleAppViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)configureView
{
    // We will display the users profile attributes if they are logged in:
    //  - given_name
    //  - family_name
    //  - email
    
    if ([[SampleAppCurrentSession session] inErrorState])
    {
        
    }
    else
    {
        if( [[SampleAppCurrentSession session] isAuthenticated])
        {
            NSString *email = [[SampleAppCurrentSession session] getValueForAttribute:@"email"];
            NSString *givenName = [[SampleAppCurrentSession session] getValueForAttribute:@"given_name"];
            NSString *familyName = [[SampleAppCurrentSession session] getValueForAttribute:@"family_name"];
            
            [self.outletEmail setText:email];
            [self.outletEmail setTextColor:[UIColor darkGrayColor]];
            [self.outletFirstName setText:givenName];
            [self.outletFirstName setTextColor:[UIColor darkGrayColor]];
            [self.outletLastName setText:familyName];
            [self.outletLastName setTextColor:[UIColor darkGrayColor]];
            [self.outletSignOutButton setEnabled:YES];
            
            sessionExpiry = [NSTimer scheduledTimerWithTimeInterval:1 target:self selector:@selector(sessionCountdown:) userInfo:nil repeats:YES];
            
        } else {
            
            [self.outletEmail setText:@"[not logged in]"];
            [self.outletEmail setTextColor:[UIColor lightGrayColor]];
            [self.outletFirstName setText:@"[not logged in]"];
            [self.outletFirstName setTextColor:[UIColor lightGrayColor]];
            [self.outletLastName setText:@"[not logged in]"];
            [self.outletLastName setTextColor:[UIColor lightGrayColor]];
            [self.outletSignOutButton setEnabled:NO];
            
            [self.outletSessionLifetime setText:@"[not logged in]"];
            [self.outletSessionLifetime setTextColor:[UIColor lightGrayColor]];
            [sessionExpiry invalidate];
        }
    }
    
}

- (void)viewDidAppear:(BOOL)animated
{
    [self configureView];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)actionSignInButton
{
    
    // Here we redirect the user for authentication, we need some configuration information here though:
    //  - baseUrl / Issuer: The base URL for the authorization endpoint on the AS.  Will have /as/authorization.oauth2 appended.
    NSString *issuer = @"https://sso.meycloud.net:9031";
    [[SampleAppCurrentSession session] setIssuer:issuer];
    
    //  - response_type: token and/or id_token (we have a really basic use-case, authentication only, no API security)
    //  - scope: openid profile email (space delimited)
    NSString *scope = @"openid profile email";

    //  - client_id: the oauth2 client sampleapp_im_client
    NSString *clientId = @"sampleapp_im_client";
    [[SampleAppCurrentSession session] setClient_id:clientId];

    //  - redirect_uri: the endpoint to rturn the token - this is the app callback url com.pingidentity.OIDCSampleApp://oidc_callback
    NSString *redirectUri = @"com.pingidentity.OIDCSampleApp://oidc_callback";
    
    //  - nonce: a random value that we can use to check comes back the same abcdefghijklmnopqrstuvwyxz
    NSString *nonce = @"abcdefghijklmnopqrstuvwyxz";
    [[SampleAppCurrentSession session] setNonce:nonce];
    
    //  - here we could also define "idp" or "pfidpadapterid" to use a specific adapter or idp connection.
    OAuth2Client *implicitProfile = [[OAuth2Client alloc] init];
    [implicitProfile setBaseUrl:issuer];
    [implicitProfile setAuthorizationEndpoint:@"/as/authorization.oauth2"];
    [implicitProfile setOAuthParameter:kOAuth2ParamClientId value:clientId];
    [implicitProfile setOAuthParameter:kOAuth2ParamRedirectUri value:redirectUri];
    [implicitProfile setOAuthParameter:kOAuth2ParamScope value:scope];
    [implicitProfile setOAuthParameter:kOAuth2ParamResponseType value:@"id_token"];
    [implicitProfile setOAuthParameter:kOAuth2ParamNonce value:nonce];
    
    [[SampleAppCurrentSession session] setOIDCImplicitProfile:implicitProfile];

    // Step 1 - Build the token url we need to redirect the user to
    NSString *authorizationUrl = [implicitProfile buildAuthorizationRedirectUrl];
    NSLog(@"Calling authorization url: %@", authorizationUrl);
    
    // Step 2 - Redirect the user, the user will return in the SampleAppAppDelegate.m file
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:authorizationUrl]];
    CFRunLoopRun();

    // We have returned from Safari and should have an authenticated user object
    if([[SampleAppCurrentSession session] inErrorState])
    {
        // Error - handle it
        NSString *errorText = [[[[SampleAppCurrentSession session] getLastError] stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding] stringByReplacingOccurrencesOfString:@"+" withString:@" "];
        NSLog(@"An error occurred: %@", errorText);
        [self.outletMessages setText:errorText];
        [self.outletMessages setTextColor:[UIColor redColor]];
    }
    
    [self.view setNeedsDisplay];
    [self configureView];
}

- (IBAction)actionSignOutButton {
    
    [[SampleAppCurrentSession session] logout];
    [self.view setNeedsDisplay];
    [self configureView];
    
}

- (void)sessionCountdown:(NSTimer *)timer
{

    NSDate *expires = [NSDate dateWithTimeIntervalSince1970:[[[SampleAppCurrentSession session] getValueForAttribute:@"exp"] doubleValue]];
    NSTimeInterval interval = [expires timeIntervalSinceNow];
    
    if (interval < 0.0)
    {
        [self.outletSessionLifetime setText:@"Session Expired!"];
        [self.outletSessionLifetime setTextColor:[UIColor redColor]];
        [self.outletEmail setTextColor:[UIColor redColor]];
        [self.outletFirstName setTextColor:[UIColor redColor]];
        [self.outletLastName setTextColor:[UIColor redColor]];
        [timer invalidate];
    }
    else
    {
        NSString *sessionMessage = [NSString stringWithFormat:@"Expires in %.2f seconds", interval];
        [self.outletSessionLifetime setText:sessionMessage];
        [self.outletSessionLifetime setTextColor:[UIColor darkGrayColor]];
    }
}

@end
