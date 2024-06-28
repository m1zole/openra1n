/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2022 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <errno.h>
#include <fcntl.h>              // open
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>             // exit, strtoull
#include <string.h>             // strlen, strerror, memcpy, memmove
#include <unistd.h>             // close
#include <wordexp.h>
#include <sys/mman.h>           // mmap, munmap
#include <sys/stat.h>           // fstst
#include <getopt.h>

#include "payloads/kpf.bin.h"
#include "payloads/ramdisk.dmg.h"
#include "payloads/overlay.dmg.h"
#include "payloads/legacy_kpf.bin.h"
#include "payloads/legacy_ramdisk.dmg.h"
#include "payloads/kok3shi9.bin.h"

#define checkrain_option_none               0x00000000
// KPF options
#define checkrain_option_verbose_boot       (1 << 0)

// Global options
#define checkrain_option_safemode           (1 << 0)

enum AUTOBOOT_STAGE {
    NONE,
    SETUP_STAGE_FUSE,
    SETUP_STAGE_SEP,
    SEND_STAGE_KPF,
    SETUP_STAGE_KPF,
    SEND_STAGE_RAMDISK,
    SETUP_STAGE_RAMDISK,
    SEND_STAGE_OVERLAY,
    SETUP_STAGE_OVERLAY,
    SETUP_STAGE_KPF_FLAGS,
    SETUP_STAGE_CHECKRAIN_FLAGS,
    SETUP_STAGE_XARGS,
    BOOTUP_STAGE,
    USB_TRANSFER_ERROR,
};

enum AUTOBOOT_STAGE CURRENT_STAGE = NONE;

static bool use_autoboot = false;
static bool use_safemode = false;
static bool use_verbose_boot = false;
static bool use_legacy   = false;
static bool use_kok3shi9 = false;

static char* bootArgs = NULL;
static uint32_t kpf_flags = checkrain_option_none;
static uint32_t checkra1n_flags = checkrain_option_none;

static char *override_kpf = NULL;
static char *override_ramdisk = NULL;
static char *override_overlay = NULL;

//thanks to palera1n!
//https://github.com/palera1n/palera1n/blob/main/include/palerain.h#L143
typedef struct {
    unsigned char* ptr; /* pointer to the override file in memory */
    uint32_t len; /* length of override file */
} override_file_t;

unsigned char *load_kpf = NULL;
unsigned int load_kpf_len = 0;
unsigned char *load_ramdisk = NULL;
unsigned int load_ramdisk_len = 0;
unsigned char *load_overlay = NULL;
unsigned int load_overlay_len = 0;

#define LOG(fmt, ...) do { fprintf(stderr, "\x1b[1;96m" fmt "\x1b[0m\n", ##__VA_ARGS__); } while(0)
#define ERR(fmt, ...) do { fprintf(stderr, "\x1b[1;91m" fmt "\x1b[0m\n", ##__VA_ARGS__); } while(0)

#ifdef DEVBUILD
#define DEVLOG(fmt, ...) do { fprintf(stderr, "\x1b[1;95m" fmt "\x1b[0m\n", ##__VA_ARGS__); } while(0)
#else
#define DEVLOG(fmt, ...)
#endif

// Keep in sync with Pongo
#define PONGO_USB_VENDOR    0x05ac
#define PONGO_USB_PRODUCT   0x4141
#define CMD_LEN_MAX         512
#define UPLOADSZ_MAX        (1024 * 1024 * 128)

static uint8_t gBlockIO = 1;

typedef struct stuff stuff_t;

static void io_start(stuff_t *stuff);
static void io_stop(stuff_t *stuff);

/********** ********** ********** ********** **********
 * Platform-specific code must define:
 * - usb_ret_t
 * - usb_device_handle_t
 * - USB_RET_SUCCESS
 * - USB_RET_NOT_RESPONDING
 * - usb_strerror
 * - struct stuff, which must contain the fields "handle"
 *   and "th", but may contain more than just that.
 * - USBControlTransfer
 * - USBBulkUpload
 * - pongoterm_main
 ********** ********** ********** ********** **********/

#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOCFPlugIn.h>

typedef IOReturn usb_ret_t;
typedef IOUSBInterfaceInterface245 **usb_device_handle_t;

#define USB_RET_SUCCESS         KERN_SUCCESS
#define USB_RET_NOT_RESPONDING  kIOReturnNotResponding

static inline __attribute__((always_inline)) const char *usb_strerror(usb_ret_t err)
{
    return mach_error_string(err);
}

static inline __attribute__((always_inline)) usb_ret_t USBControlTransfer(usb_device_handle_t handle, uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint32_t wLength, void *data, uint32_t *wLenDone)
{
    IOUSBDevRequest request =
    {
        .bmRequestType = bmRequestType,
        .bRequest = bRequest,
        .wValue = wValue,
        .wIndex = wIndex,
        .wLength = wLength,
        .pData = data,
    };
    usb_ret_t ret = (*handle)->ControlRequest(handle, 0, &request);
    if(wLenDone) *wLenDone = request.wLenDone;
    return ret;
}

static inline __attribute__((always_inline)) usb_ret_t USBBulkUpload(usb_device_handle_t handle, void *data, uint32_t len)
{
    return (*handle)->WritePipe(handle, 2, data, len);
}

struct stuff
{
    pthread_t th;
    volatile uint64_t regID;
    IOUSBDeviceInterface245 **dev;
    usb_device_handle_t handle;
};

static void FoundDevice(void *refCon, io_iterator_t it)
{
    stuff_t *stuff = refCon;
    if(stuff->regID)
    {
        return;
    }
    io_service_t usbDev = MACH_PORT_NULL;
    while((usbDev = IOIteratorNext(it)))
    {
        uint64_t regID;
        kern_return_t ret = IORegistryEntryGetRegistryEntryID(usbDev, &regID);
        if(ret != KERN_SUCCESS)
        {
            ERR("IORegistryEntryGetRegistryEntryID: %s", mach_error_string(ret));
            goto next;
        }
        SInt32 score = 0;
        IOCFPlugInInterface **plugin = NULL;
        ret = IOCreatePlugInInterfaceForService(usbDev, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
        if(ret != KERN_SUCCESS)
        {
            ERR("IOCreatePlugInInterfaceForService(usbDev): %s", mach_error_string(ret));
            goto next;
        }
        HRESULT result = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID), (LPVOID*)&stuff->dev);
        (*plugin)->Release(plugin);
        if(result != 0)
        {
            ERR("QueryInterface(dev): 0x%x", result);
            goto next;
        }
        ret = (*stuff->dev)->USBDeviceOpenSeize(stuff->dev);
        if(ret != KERN_SUCCESS)
        {
            ERR("USBDeviceOpenSeize: %s", mach_error_string(ret));
        }
        else
        {
            ret = (*stuff->dev)->SetConfiguration(stuff->dev, 1);
            if(ret != KERN_SUCCESS)
            {
                ERR("SetConfiguration: %s", mach_error_string(ret));
            }
            else
            {
                IOUSBFindInterfaceRequest request =
                {
                    .bInterfaceClass = kIOUSBFindInterfaceDontCare,
                    .bInterfaceSubClass = kIOUSBFindInterfaceDontCare,
                    .bInterfaceProtocol = kIOUSBFindInterfaceDontCare,
                    .bAlternateSetting = kIOUSBFindInterfaceDontCare,
                };
                io_iterator_t iter = MACH_PORT_NULL;
                ret = (*stuff->dev)->CreateInterfaceIterator(stuff->dev, &request, &iter);
                if(ret != KERN_SUCCESS)
                {
                    ERR("CreateInterfaceIterator: %s", mach_error_string(ret));
                }
                else
                {
                    io_service_t usbIntf = MACH_PORT_NULL;
                    while((usbIntf = IOIteratorNext(iter)))
                    {
                        ret = IOCreatePlugInInterfaceForService(usbIntf, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
                        IOObjectRelease(usbIntf);
                        if(ret != KERN_SUCCESS)
                        {
                            ERR("IOCreatePlugInInterfaceForService(usbIntf): %s", mach_error_string(ret));
                            continue;
                        }
                        result = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID), (LPVOID*)&stuff->handle);
                        (*plugin)->Release(plugin);
                        if(result != 0)
                        {
                            ERR("QueryInterface(intf): 0x%x", result);
                            continue;
                        }
                        ret = (*stuff->handle)->USBInterfaceOpen(stuff->handle);
                        if(ret != KERN_SUCCESS)
                        {
                            ERR("USBInterfaceOpen: %s", mach_error_string(ret));
                        }
                        else
                        {
                            io_start(stuff);
                            stuff->regID = regID;
                            while((usbIntf = IOIteratorNext(iter))) IOObjectRelease(usbIntf);
                            IOObjectRelease(iter);
                            while((usbDev = IOIteratorNext(it))) IOObjectRelease(usbDev);
                            IOObjectRelease(usbDev);
                            return;
                        }
                        (*stuff->handle)->Release(stuff->handle);
                        stuff->handle = NULL;
                    }
                    IOObjectRelease(iter);
                }
            }
        }

    next:;
        if(stuff->dev)
        {
            (*stuff->dev)->USBDeviceClose(stuff->dev);
            (*stuff->dev)->Release(stuff->dev);
            stuff->dev = NULL;
        }
        IOObjectRelease(usbDev);
    }
}

static void LostDevice(void *refCon, io_iterator_t it)
{
    stuff_t *stuff = refCon;
    io_service_t usbDev = MACH_PORT_NULL;
    while((usbDev = IOIteratorNext(it)))
    {
        uint64_t regID;
        kern_return_t ret = IORegistryEntryGetRegistryEntryID(usbDev, &regID);
        IOObjectRelease(usbDev);
        if(ret == KERN_SUCCESS && stuff->regID == regID)
        {
            io_stop(stuff);
            stuff->regID = 0;
            (*stuff->handle)->USBInterfaceClose(stuff->handle);
            (*stuff->handle)->Release(stuff->handle);
            (*stuff->dev)->USBDeviceClose(stuff->dev);
            (*stuff->dev)->Release(stuff->dev);
        }
    }
}

static inline __attribute__((always_inline)) int pongoterm_main(void)
{
    kern_return_t ret;
    stuff_t stuff = {};
    io_iterator_t found, lost;
    NSDictionary *dict =
    @{
        @"IOProviderClass": @"IOUSBDevice",
        @"idVendor":  @PONGO_USB_VENDOR,
        @"idProduct": @PONGO_USB_PRODUCT,
    };
    CFDictionaryRef cfdict = (__bridge CFDictionaryRef)dict;
    IONotificationPortRef notifyPort = IONotificationPortCreate(kIOMasterPortDefault);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(notifyPort), kCFRunLoopDefaultMode);

    CFRetain(cfdict);
    ret = IOServiceAddMatchingNotification(notifyPort, kIOFirstMatchNotification, cfdict, &FoundDevice, &stuff, &found);
    if(ret != KERN_SUCCESS)
    {
        ERR("IOServiceAddMatchingNotification: %s", mach_error_string(ret));
        return -1;
    }
    FoundDevice(&stuff, found);

    CFRetain(cfdict);
    ret = IOServiceAddMatchingNotification(notifyPort, kIOTerminatedNotification, cfdict, &LostDevice, &stuff, &lost);
    if(ret != KERN_SUCCESS)
    {
        ERR("IOServiceAddMatchingNotification: %s", mach_error_string(ret));
        return -1;
    }
    LostDevice(&stuff, lost);
    CFRunLoopRun();
    return -1;
}

static void write_stdout(char *buf, uint32_t len)
{
    while(len > 0)
    {
        ssize_t s = write(1, buf, len);
        if(s < 0)
        {
            ERR("write: %s", strerror(errno));
            exit(-1); // TODO: ok with libusb?
        }
        buf += s;
        len -= s;
    }
}

static override_file_t override_file(const char* file)
{
    override_file_t ret;
    FILE *fp = fopen(file, "rb");
    if (fp == NULL) {
		ERR("File doesn't find.\n");
        ret.len = 0;
        ret.ptr = NULL;
		return ret;
	}
    fseek(fp, 0, SEEK_END);
    ret.len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
    ret.ptr = malloc(ret.len);
	fread(ret.ptr, ret.len, 1, fp);
	fclose(fp);
    return ret;
}

static void* io_main(void *arg)
{
    if(override_kpf == NULL)
    {
        if(use_kok3shi9)
        {
            LOG("kok3shi module");
            load_kpf = payloads_kok3shi9_bin;
            load_kpf_len = payloads_kok3shi9_bin_len;
        }
        else if(use_legacy)
        {
            LOG("legacy kpf");
            load_kpf = payloads_legacy_kpf_bin;
            load_kpf_len = payloads_legacy_kpf_bin_len;
        }
        else
        {
            LOG("nomal kpf");
            load_kpf = payloads_kpf_bin;
            load_kpf_len = payloads_kpf_bin_len;
        }
    }
    else
    {
        override_file_t kpf = override_file(override_kpf);
        load_kpf = kpf.ptr;
        load_kpf_len = kpf.len;
    }
    
    if(override_ramdisk == NULL)
    {
        if(use_legacy)
        {
            LOG("legacy ramdisk");
            load_ramdisk = payloads_legacy_ramdisk_dmg;
            load_ramdisk_len = payloads_legacy_ramdisk_dmg_len;
        }
        else
        {
            LOG("bakera1n's ramdisk");
            load_ramdisk = payloads_ramdisk_dmg;
            load_ramdisk_len  = payloads_ramdisk_dmg_len;
        }
    }
    else
    {
        override_file_t ramdisk = override_file(override_ramdisk);
        load_ramdisk = ramdisk.ptr;
        load_ramdisk_len = ramdisk.len;
    }
    if(override_overlay == NULL)
    {
        load_overlay = payloads_overlay_dmg;
        load_overlay_len = payloads_overlay_dmg_len;
    } 
    else
    {
        override_file_t overlay = override_file(override_overlay);
        load_overlay = overlay.ptr;
        load_overlay_len = overlay.len;
    }
    stuff_t *stuff = arg;
    int r = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    if(r != 0)
    {
        ERR("pthread_setcancelstate: %s", strerror(r));
        exit(-1); // TODO: ok with libusb?
    }
    LOG("[Connected]");
    usb_ret_t ret = USB_RET_SUCCESS;
    char prompt[64] = "> ";
    uint32_t plen = 2;
    while(1)
    {
        char buf[0x2000] = {};
        uint32_t outpos = 0;
        uint32_t outlen = 0;
        uint8_t in_progress = 1;
        while(in_progress)
        {
            ret = USBControlTransfer(stuff->handle, 0xa1, 2, 0, 0, (uint32_t)sizeof(in_progress), &in_progress, NULL);
            if(ret == USB_RET_SUCCESS)
            {
                ret = USBControlTransfer(stuff->handle, 0xa1, 1, 0, 0, 0x1000, buf + outpos, &outlen);
                if(ret == USB_RET_SUCCESS)
                {
                    write_stdout(buf + outpos, outlen);
                    outpos += outlen;
                    if(outpos > 0x1000)
                    {
                        memmove(buf, buf + outpos - 0x1000, 0x1000);
                        outpos = 0x1000;
                    }
                }
            }
            if(ret != USB_RET_SUCCESS)
            {
                goto bad;
            }
        }
        if(outpos > 0)
        {
            // Record prompt
            uint32_t start = outpos;
            for(uint32_t end = outpos > 64 ? outpos - 64 : 0; start > end; --start)
            {
                if(buf[start-1] == '\n')
                {
                    break;
                }
            }
            plen = outpos - start;
            memcpy(prompt, buf + start, plen);
        }
        else
        {
            // Re-emit prompt
            write_stdout(prompt, plen);
        }
        ret = USBControlTransfer(stuff->handle, 0x21, 4, 0xffff, 0, 0, NULL, NULL);
        if(ret != USB_RET_SUCCESS)
        {
            goto bad;
        }
        r = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        if(r != 0)
        {
            ERR("pthread_setcancelstate: %s", strerror(r));
            exit(-1); // TODO: ok with libusb?
        }
        size_t len = 0;
        while(1)
        {
            if(use_autoboot)
                break;
            
            char ch;
            ssize_t s = read(0, &ch, 1);
            if(s == 0)
            {
                break;
            }
            if(s < 0)
            {
                if(errno == EINTR)
                {
                    return NULL;
                }
                ERR("read: %s", strerror(errno));
                exit(-1); // TODO: ok with libusb?
            }
            if(len < sizeof(buf))
            {
                buf[len] = ch;
            }
            ++len;
            if(ch == '\n')
            {
                break;
            }
        }
        r = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
        if(r != 0)
        {
            ERR("pthread_setcancelstate: %s", strerror(r));
            exit(-1); // TODO: ok with libusb?
        }
        if(len == 0)
        {
            if(use_autoboot)
            {
                
                {
                    if(CURRENT_STAGE == NONE)
                        CURRENT_STAGE = SETUP_STAGE_FUSE;
                    
                    if(CURRENT_STAGE == SETUP_STAGE_FUSE)
                    {
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("fuse lock\n")), "fuse lock\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "fuse lock");
                            CURRENT_STAGE = SETUP_STAGE_SEP;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_SEP)
                    {
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("sep auto\n")), "sep auto\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "sep auto");
                            CURRENT_STAGE = SEND_STAGE_KPF;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SEND_STAGE_KPF)
                    {
                        size_t size = load_kpf_len;
                        ret = USBControlTransfer(stuff->handle, 0x21, 1, 0, 0, 4, &size, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            ret = USBBulkUpload(stuff->handle, load_kpf, load_kpf_len);
                            if(ret == USB_RET_SUCCESS)
                            {
                                LOG("/send %s\n%s: %llu bytes", "kpf", "kpf", (unsigned long long)load_kpf_len);
                                CURRENT_STAGE = SETUP_STAGE_KPF;
                            }
                            else
                            {
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                            }
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_KPF)
                    {
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("modload\n")), "modload\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "modload");
                            if(use_kok3shi9)
                            {
                                CURRENT_STAGE = BOOTUP_STAGE;
                            }
                            else
                            {
                                CURRENT_STAGE = SEND_STAGE_RAMDISK;
                            }
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SEND_STAGE_RAMDISK)
                    {
                        size_t size = load_ramdisk_len;
                        ret = USBControlTransfer(stuff->handle, 0x21, 1, 0, 0, 4, &size, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            ret = USBBulkUpload(stuff->handle, load_ramdisk, load_ramdisk_len);
                            if(ret == USB_RET_SUCCESS)
                            {
                                LOG("/send %s\n%s: %llu bytes", "ramdisk", "ramdisk", (unsigned long long)load_ramdisk_len);
                                CURRENT_STAGE = SETUP_STAGE_RAMDISK;
                            }
                            else
                            {
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                            }
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_RAMDISK)
                    {
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("ramdisk\n")), "ramdisk\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "ramdisk");
                            if(use_legacy){
                                CURRENT_STAGE = SETUP_STAGE_KPF_FLAGS;
                            } else{
                                CURRENT_STAGE = SEND_STAGE_OVERLAY;
                            }
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SEND_STAGE_OVERLAY)
                    {
                        size_t size = load_overlay_len;
                        ret = USBControlTransfer(stuff->handle, 0x21, 1, 0, 0, 4, &size, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            ret = USBBulkUpload(stuff->handle, load_overlay, load_overlay_len);
                            if(ret == USB_RET_SUCCESS)
                            {
                                LOG("/send %s\n%s: %llu bytes", "overlay", "overlay", (unsigned long long)load_overlay_len);
                                CURRENT_STAGE = SETUP_STAGE_OVERLAY;
                            }
                            else
                            {
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                            }
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_OVERLAY)
                    {
                        
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("overlay\n")), "overlay\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "overlay");
                            CURRENT_STAGE = SETUP_STAGE_KPF_FLAGS;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_KPF_FLAGS)
                    {
                        
                        if(use_verbose_boot)
                        {
                            kpf_flags |= checkrain_option_verbose_boot;
                        }
                        
                        char str[64];
                        memset(&str, 0x0, 64);
                        sprintf(str, "kpf_flags 0x%08x\n", kpf_flags);
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen(str)), str, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            memset(&str, 0x0, 64);
                            sprintf(str, "kpf_flags 0x%08x", kpf_flags);
                            LOG("%s", str);
                            CURRENT_STAGE = SETUP_STAGE_CHECKRAIN_FLAGS;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == SETUP_STAGE_CHECKRAIN_FLAGS)
                    {
                        if(use_safemode)
                        {
                            checkra1n_flags |= checkrain_option_safemode;
                        }
                        
                        char str[64];
                        memset(&str, 0x0, 64);
                        sprintf(str, "checkra1n_flags 0x%08x\n", checkra1n_flags);
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen(str)), str, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            memset(&str, 0x0, 64);
                            sprintf(str, "checkra1n_flags 0x%08x", checkra1n_flags);
                            LOG("%s", str);
                            CURRENT_STAGE = SETUP_STAGE_XARGS;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    
                    if(CURRENT_STAGE == SETUP_STAGE_XARGS)
                    {
                        char str[256];
                        memset(&str, 0x0, 256);
                        
                        char* defaultBootArgs = NULL;
                        
                        if(use_legacy)
                        {
                            defaultBootArgs = "rootdev=md0";
                        }
                        
                        if(defaultBootArgs)
                        {
                            if(strlen(defaultBootArgs) > 256) {
                                ERR("defaultBootArgs is too large!");
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                                continue;
                            }
                            sprintf(str, "%s", defaultBootArgs);
                        }
                        
                        if(bootArgs)
                        {
                            // sprintf(str, "xargs %s\n", bootArgs);
                            if((strlen(str) + strlen(bootArgs)) > 256) {
                                ERR("bootArgs is too large!");
                                CURRENT_STAGE = USB_TRANSFER_ERROR;
                                continue;
                            }
                            sprintf(str, "%s %s", str, bootArgs);
                        }
                        
                        
                        char xstr[256 + 7];
                        memset(&xstr, 0x0, 256 + 7);
                        sprintf(xstr, "xargs %s\n", str);
                        
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen(xstr)), xstr, NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("xargs %s", str);
                            CURRENT_STAGE = BOOTUP_STAGE;
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == BOOTUP_STAGE)
                    {
                        ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)(strlen("bootx\n")), "bootx\n", NULL);
                        if(ret == USB_RET_SUCCESS)
                        {
                            LOG("%s", "bootx");
                            exit(0);
                        }
                        else
                        {
                            CURRENT_STAGE = USB_TRANSFER_ERROR;
                        }
                        continue;
                    }
                    
                    if(CURRENT_STAGE == USB_TRANSFER_ERROR)
                    {
                        ERR("WTF?!");
                        exit(-1);
                    }
                }
            }
            
            exit(0); // TODO: ok with libusb?
        }
        if(len > sizeof(buf))
        {
            ERR("Discarding command of >%zu chars", sizeof(buf));
            continue;
        }
        if(buf[0] == '/')
        {
            buf[len-1] = '\0';
            wordexp_t we;
            r = wordexp(buf + 1, &we, WRDE_SHOWERR | WRDE_UNDEF);
            if(r != 0)
            {
                ERR("wordexp: %d", r);
                continue;
            }
            bool show_help = false;
            if(we.we_wordc == 0)
            {
                show_help = true;
            }
            else if(strcmp(we.we_wordv[0], "send") == 0)
            {
                if(we.we_wordc == 1)
                {
                    LOG("Usage: /send [file]");
                    LOG("Upload a file to PongoOS. This should be followed by a command such as \"modload\".");
                }
                else
                {
                    int fd = open(we.we_wordv[1], O_RDONLY);
                    if(fd < 0)
                    {
                        ERR("Failed to open file: %s", strerror(errno));
                    }
                    else
                    {
                        struct stat s;
                        r = fstat(fd, &s);
                        if(r != 0)
                        {
                            ERR("Failed to stat file: %s", strerror(errno));
                        }
                        else
                        {
                            void *addr = mmap(NULL, s.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
                            if(addr == MAP_FAILED)
                            {
                                ERR("Failed to map file: %s", strerror(errno));
                            }
                            else
                            {
                                uint32_t newsz = s.st_size;
                                ret = USBControlTransfer(stuff->handle, 0x21, 1, 0, 0, 4, &newsz, NULL);
                                if(ret == USB_RET_SUCCESS)
                                {
                                    ret = USBBulkUpload(stuff->handle, addr, s.st_size);
                                    if(ret == USB_RET_SUCCESS)
                                    {
                                        LOG("Uploaded %llu bytes", (unsigned long long)s.st_size);
                                    }
                                }
                                munmap(addr, s.st_size);
                            }
                        }
                        close(fd);
                    }
                }
            }
            else
            {
                ERR("Unrecognised command: /%s", we.we_wordv[0]);
                show_help = true;
            }
            if(show_help)
            {
                LOG("Available commands:");
                LOG("/send [file] - Upload a file to PongoOS");
            }
            wordfree(&we);
        }
        else
        {
            if(len > CMD_LEN_MAX)
            {
                ERR("PongoOS currently only supports commands with %u characters or less", CMD_LEN_MAX);
                continue;
            }
            if(gBlockIO)
            {
                ret = USBControlTransfer(stuff->handle, 0x21, 4, 1, 0, 0, NULL, NULL);
            }
            if(ret == USB_RET_SUCCESS)
            {
                ret = USBControlTransfer(stuff->handle, 0x21, 3, 0, 0, (uint32_t)len, buf, NULL);
            }
        }
        if(ret != USB_RET_SUCCESS)
        {
            goto bad;
        }
    }
bad:;
    if(ret == USB_RET_NOT_RESPONDING)
    {
        return NULL;
    }
    ERR("USB error: %s", usb_strerror(ret));
    exit(-1); // TODO: ok with libusb?
}

static inline __attribute__((always_inline))  void io_start(stuff_t *stuff)
{
    int r = pthread_create(&stuff->th, NULL, &io_main, stuff);
    if(r != 0)
    {
        ERR("pthread_create: %s", strerror(r));
        exit(-1); // TODO: ok with libusb?
    }
}

static inline __attribute__((always_inline))  void io_stop(stuff_t *stuff)
{
    LOG("[Disconnected]");
    int r = pthread_cancel(stuff->th);
    if(r != 0)
    {
        ERR("pthread_cancel: %s", strerror(r));
        exit(-1); // TODO: ok with libusb?
    }
    r = pthread_join(stuff->th, NULL);
    if(r != 0)
    {
        ERR("pthread_join: %s", strerror(r));
        exit(-1); // TODO: ok with libusb?
    }
}

static inline __attribute__((always_inline))  void usage(const char* s)
{
    printf("Usage: %s [-ahsv] [-e <boot-args>]\n", s);
    printf("\t-h, --help\t\t\t: show usage\n");
    printf("\t-a, --autoboot\t\t\t: enable bakera1n boot mode\n");
    printf("\t-e, --extra-bootargs <args>\t: replace bootargs\n");
    printf("\t-s, --safemode\t\t\t: enable safe mode\n");
    printf("\t-v, --verbose-boot\t\t: enable verbose boot\n");
    
    return;
}

int main(int argc, char** argv)
{
    int opt = 0;
    static struct option longopts[] = {
        { "help",               no_argument,       NULL, 'h' },
        { "autoboot",           no_argument,       NULL, 'a' },
        { "extra-bootargs",     required_argument, NULL, 'e' },
        { "safemode",           no_argument,       NULL, 's' },
        { "legacy",             no_argument,       NULL, 'l' },
        { "kok3shi9",           no_argument,       NULL, '9' },
        { "verbose-boot",       no_argument,       NULL, 'v' },
        { "override_kpf",       required_argument, NULL, 'k' },
        { "override-rdk",       required_argument, NULL, 'r' },
        { "override-ovl",       required_argument, NULL, 'o' },
        { NULL, 0, NULL, 0 }
    };
    
    while ((opt = getopt_long(argc, argv, "alh9e:svk:r:o:i:", longopts, NULL)) > 0) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                return 0;
                
            case 'a':
                use_autoboot = 1;
                LOG("selected: autoboot mode");
                break;

            case 'e':
                if (optarg) {
                    bootArgs = strdup(optarg);
                    LOG("set bootArgs: [%s]", bootArgs);
                }
                break;

            case 's':
                use_safemode = 1;
                break;
                
            case 'v':
                use_verbose_boot = 1;
                break;

            case 'k':
                override_kpf = strdup(optarg);
                LOG("kpf:     [%s]", override_kpf);
                break;

            case 'r':
                override_ramdisk = strdup(optarg);
                LOG("ramdisk: [%s]", override_ramdisk);
                break;

            case 'o':
                override_overlay = strdup(optarg);
                LOG("overlay: [%s]", override_overlay);
                break;

            case '9':
                use_kok3shi9 = 1;

            case 'l':
                use_legacy = 1;
                break;

            default:
                break;
        }
    }
    
    return pongoterm_main();
}
