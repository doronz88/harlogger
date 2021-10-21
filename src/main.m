#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#include <notify.h>
#include <stdio.h>

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		NSArray<NSString *> *arguments = [[NSProcessInfo processInfo] arguments];

		if (arguments.count <= 1) {
			NSLog(@"Usage: harlogger <duration> [--infinite]");
			return 1;
		}

		NSDate *date;

		if ([arguments containsObject:@"--infinite"]) {
			NSLog(@"Starting HAR logging for infinity");

			NSDateComponents *comps = [NSDateComponents new];
			[comps setDay:1];
			[comps setMonth:1];
			[comps setYear:9999];
			date = [[NSCalendar currentCalendar] dateFromComponents:comps];
			
		} else {
			double duration = [arguments[1] doubleValue];
			NSLog(@"Starting HAR logging for %f seconds", duration);

			date = [NSDate dateWithTimeIntervalSinceNow:duration];
		}

		CFPreferencesSetValue(CFSTR("har-capture-global"), (__bridge CFPropertyListRef)date, 
			CFSTR("com.apple.CFNetwork"), CFSTR("mobile"), kCFPreferencesAnyHost);

		if (notify_post("com.apple.CFNetwork.har-capture-update")) {
			NSLog(@"Failed to post notification");
			return 1;
		}

		return 0;
	}
}
