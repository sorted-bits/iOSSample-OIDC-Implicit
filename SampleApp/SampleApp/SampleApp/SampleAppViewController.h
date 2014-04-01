//
//  SampleAppViewController.h
//  SampleApp
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface SampleAppViewController : UIViewController
{
    NSTimer *sessionExpiry;
}

@property (weak, nonatomic) IBOutlet UIButton *outletSignInButton;
@property (weak, nonatomic) IBOutlet UIButton *outletSignOutButton;

@property (weak, nonatomic) IBOutlet UILabel *outletFirstName;
@property (weak, nonatomic) IBOutlet UILabel *outletLastName;
@property (weak, nonatomic) IBOutlet UILabel *outletEmail;
@property (weak, nonatomic) IBOutlet UILabel *outletSessionLifetime;
@property (weak, nonatomic) IBOutlet UITextView *outletMessages;

@end
