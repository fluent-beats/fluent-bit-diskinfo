/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Etriphany
 *  ==========
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_IN_DISKINFO_H
#define FLB_IN_DISKINFO_H

#include <stdint.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0
#define DEFAULT_PROC_PATH "/proc"

#define LINE_SIZE 256
#define BUF_SIZE  32
#define STR_KEY_WRITE "write_size"
#define STR_KEY_READ  "read_size"

struct flb_in_diskinfo_config {
    uint64_t *read_total;
    uint64_t *write_total;
    uint64_t *prev_read_total;
    uint64_t *prev_write_total;
    char *proc_path;     /* allows point to host proc file */
    char *dev_name;
    int entry;
    int interval_sec;
    int interval_nsec;
    int first_snapshot;   /* indicate this is the first collect */
};

extern struct flb_input_plugin in_diskinfo_plugin;

#endif
