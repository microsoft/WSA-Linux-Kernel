/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Linux-specific definitions for managing interactions with Microsoft's
 * Hyper-V hypervisor. The definitions in this file are specific to
 * the ARM64 architecture.  See include/asm-generic/mshyperv.h for
 * definitions are that architecture independent.
 *
 * Definitions that are specified in the Hyper-V Top Level Functional
 * Spec (TLFS) should not go in this file, but should instead go in
 * hyperv-tlfs.h.
 *
 * Copyright (C) 2021, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */

#ifndef _ASM_MSHYPERV_H
#define _ASM_MSHYPERV_H

#include <linux/types.h>
#include <linux/arm-smccc.h>
#include <asm/hyperv-tlfs.h>
#include <clocksource/arm_arch_timer.h>

#if IS_ENABLED(CONFIG_HYPERV)
void __init hyperv_early_init(void);
#else
static inline void hyperv_early_init(void) {};
#endif

/*
 * Declare calls to get and set Hyper-V VP register values on ARM64, which
 * requires a hypercall.
 */

void hv_set_vpreg(u32 reg, u64 value);
u64 hv_get_vpreg(u32 reg);
void hv_get_vpreg_128(u32 reg, struct hv_get_vp_registers_output *result);

static inline void hv_set_register(unsigned int reg, u64 value)
{
	hv_set_vpreg(reg, value);
}

static inline u64 hv_get_register(unsigned int reg)
{
	return hv_get_vpreg(reg);
}

/* Define the interrupt ID used by STIMER0 Direct Mode interrupts. This
 * value can't come from ACPI tables because it is needed before the
 * Linux ACPI subsystem is initialized.
 */
#define HYPERV_STIMER0_VECTOR  31

static inline u64 hv_get_raw_timer(void)
{
	return arch_timer_read_counter();
}

/* SMCCC hypercall parameters */
#define HV_SMCCC_FUNC_NUMBER	1
#define HV_FUNC_ID	ARM_SMCCC_CALL_VAL(			\
				ARM_SMCCC_STD_CALL,		\
				ARM_SMCCC_SMC_64,		\
				ARM_SMCCC_OWNER_VENDOR_HYP,	\
				HV_SMCCC_FUNC_NUMBER)

#include <asm-generic/mshyperv.h>

#endif
