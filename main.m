#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#include <notify.h>
#include <stdio.h>

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		NSArray<NSString *> *arguments = [[NSProcessInfo processInfo] arguments];

		if (arguments.count <= 1) {
			NSLog(@"Usage: harlogger <duration>");
			return 1;
		}

		double duration = [arguments[1] doubleValue];
		NSLog(@"Starting HAR logging for %f seconds", duration);

		CFPreferencesSetValue(CFSTR("har-capture-global"), (__bridge CFPropertyListRef)[NSDate dateWithTimeIntervalSinceNow:duration], 
			CFSTR("com.apple.CFNetwork"), CFSTR("mobile"), kCFPreferencesAnyHost);

		if (notify_post("com.apple.CFNetwork.har-capture-update")) {
			NSLog(@"Failed to post notification");
			return 1;
		}

		return 0;
	}
}
