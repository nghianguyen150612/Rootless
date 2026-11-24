/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef ROOTLESS_NAMESPACE_H
#define ROOTLESS_NAMESPACE_H

int rl_write_namespace_map(const char *path, const char *value);
int rl_effective_capability(unsigned int capability);

#endif
