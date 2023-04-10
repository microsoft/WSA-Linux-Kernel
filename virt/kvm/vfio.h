/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_VFIO_H
#define __KVM_VFIO_H

#ifdef CONFIG_KVM_VFIO

/**
 * kvm_vfio_ops_init - Initialize the KVM VFIO operations.
 *
 * This function initializes the KVM VFIO operations. It is called when the KVM
 * VFIO module is loaded.
 *
 * Returns:
 * - 0 on success.
 * - A negative error code on failure.
 */
int kvm_vfio_ops_init(void);

/**
 * kvm_vfio_ops_exit - Clean up the KVM VFIO operations.
 *
 * This function cleans up the KVM VFIO operations. It is called when the KVM
 * VFIO module is unloaded.
 */
void kvm_vfio_ops_exit(void);

#else

/**
 * kvm_vfio_ops_init - Initialize the KVM VFIO operations (dummy implementation).
 *
 * This function is a dummy implementation of kvm_vfio_ops_init, used when KVM
 * VFIO support is not enabled in the kernel.
 *
 * Returns:
 * - 0.
 */
static inline int kvm_vfio_ops_init(void)
{
	return 0;
}

/**
 * kvm_vfio_ops_exit - Clean up the KVM VFIO operations (dummy implementation).
 *
 * This function is a dummy implementation of kvm_vfio_ops_exit, used when KVM
 * VFIO support is not enabled in the kernel.
 */
static inline void kvm_vfio_ops_exit(void)
{
}

#endif

#endif
