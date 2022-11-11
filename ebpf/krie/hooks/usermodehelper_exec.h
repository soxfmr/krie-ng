/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _USERMODEHELPER_EXEC_H_
#define _USERMODEHELPER_EXEC_H_

#define PATH_MAX 4096

struct usermodehelper_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    char path[PATH_MAX];
};

memory_factory(usermodehelper_event)

SEC("kprobe/call_usermodehelper_exec")
int BPF_KPROBE(kprobe_call_usermodehelper_exec, struct subprocess_info *sub_info) {
    struct process_context_t *process_ctx = new_process_context();
    if (process_ctx == NULL) {
        // should never happen, ignore
        return 0;
    }

    struct usermodehelper_event_t *event = new_usermodehelper_event();
    if (event == NULL) {
        // ignore, should not happen
        return 0;
    }

    event->event.type = EVENT_CALL_UMH;
    bpf_core_read_str(&event->path, sizeof(event->path), &sub_info->path);
    fill_process_context(process_ctx);

    int perf_ret;
    send_event_ptr(ctx, event->event.type, event);

    return 0;
}

#endif