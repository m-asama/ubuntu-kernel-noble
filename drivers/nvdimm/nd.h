/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright(c) 2013-2015 Intel Corporation. All rights reserved.
 */
#ifndef __ND_H__
#define __ND_H__
#include <linux/libnvdimm.h>
#include <linux/badblocks.h>
#include <linux/blkdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/ndctl.h>
#include <linux/types.h>
#include <linux/nd.h>
#include "label.h"

enum {
	/*
	 * Limits the maximum number of block apertures a dimm can
	 * support and is an input to the geometry/on-disk-format of a
	 * BTT instance
	 */
	ND_MAX_LANES = 256,
	INT_LBASIZE_ALIGNMENT = 64,
	NVDIMM_IO_ATOMIC = 1,
};

struct nvdimm_drvdata {
	struct device *dev;
	int nslabel_size;
	struct nd_cmd_get_config_size nsarea;
	void *data;
	bool cxl;
	int ns_current, ns_next;
	struct resource dpa;
	struct kref kref;
};

static inline const u8 *nsl_ref_name(struct nvdimm_drvdata *ndd,
				     struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return nd_label->cxl.name;
	return nd_label->efi.name;
}

static inline u8 *nsl_get_name(struct nvdimm_drvdata *ndd,
			       struct nd_namespace_label *nd_label, u8 *name)
{
	if (ndd->cxl)
		return memcpy(name, nd_label->cxl.name, NSLABEL_NAME_LEN);
	return memcpy(name, nd_label->efi.name, NSLABEL_NAME_LEN);
}

static inline u8 *nsl_set_name(struct nvdimm_drvdata *ndd,
			       struct nd_namespace_label *nd_label, u8 *name)
{
	if (!name)
		return NULL;
	if (ndd->cxl)
		return memcpy(nd_label->cxl.name, name, NSLABEL_NAME_LEN);
	return memcpy(nd_label->efi.name, name, NSLABEL_NAME_LEN);
}

static inline u32 nsl_get_slot(struct nvdimm_drvdata *ndd,
			       struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return __le32_to_cpu(nd_label->cxl.slot);
	return __le32_to_cpu(nd_label->efi.slot);
}

static inline void nsl_set_slot(struct nvdimm_drvdata *ndd,
				struct nd_namespace_label *nd_label, u32 slot)
{
	if (ndd->cxl)
		nd_label->cxl.slot = __cpu_to_le32(slot);
	else
		nd_label->efi.slot = __cpu_to_le32(slot);
}

static inline u64 nsl_get_checksum(struct nvdimm_drvdata *ndd,
				   struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return __le64_to_cpu(nd_label->cxl.checksum);
	return __le64_to_cpu(nd_label->efi.checksum);
}

static inline void nsl_set_checksum(struct nvdimm_drvdata *ndd,
				    struct nd_namespace_label *nd_label,
				    u64 checksum)
{
	if (ndd->cxl)
		nd_label->cxl.checksum = __cpu_to_le64(checksum);
	else
		nd_label->efi.checksum = __cpu_to_le64(checksum);
}

static inline u32 nsl_get_flags(struct nvdimm_drvdata *ndd,
				struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return __le32_to_cpu(nd_label->cxl.flags);
	return __le32_to_cpu(nd_label->efi.flags);
}

static inline void nsl_set_flags(struct nvdimm_drvdata *ndd,
				 struct nd_namespace_label *nd_label, u32 flags)
{
	if (ndd->cxl)
		nd_label->cxl.flags = __cpu_to_le32(flags);
	else
		nd_label->efi.flags = __cpu_to_le32(flags);
}

static inline u64 nsl_get_dpa(struct nvdimm_drvdata *ndd,
			      struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return __le64_to_cpu(nd_label->cxl.dpa);
	return __le64_to_cpu(nd_label->efi.dpa);
}

static inline void nsl_set_dpa(struct nvdimm_drvdata *ndd,
			       struct nd_namespace_label *nd_label, u64 dpa)
{
	if (ndd->cxl)
		nd_label->cxl.dpa = __cpu_to_le64(dpa);
	else
		nd_label->efi.dpa = __cpu_to_le64(dpa);
}

static inline u64 nsl_get_rawsize(struct nvdimm_drvdata *ndd,
				  struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return __le64_to_cpu(nd_label->cxl.rawsize);
	return __le64_to_cpu(nd_label->efi.rawsize);
}

static inline void nsl_set_rawsize(struct nvdimm_drvdata *ndd,
				   struct nd_namespace_label *nd_label,
				   u64 rawsize)
{
	if (ndd->cxl)
		nd_label->cxl.rawsize = __cpu_to_le64(rawsize);
	else
		nd_label->efi.rawsize = __cpu_to_le64(rawsize);
}

static inline u64 nsl_get_isetcookie(struct nvdimm_drvdata *ndd,
				     struct nd_namespace_label *nd_label)
{
	/* WARN future refactor attempts that break this assumption */
	if (dev_WARN_ONCE(ndd->dev, ndd->cxl,
			  "CXL labels do not use the isetcookie concept\n"))
		return 0;
	return __le64_to_cpu(nd_label->efi.isetcookie);
}

static inline void nsl_set_isetcookie(struct nvdimm_drvdata *ndd,
				      struct nd_namespace_label *nd_label,
				      u64 isetcookie)
{
	if (!ndd->cxl)
		nd_label->efi.isetcookie = __cpu_to_le64(isetcookie);
}

static inline bool nsl_validate_isetcookie(struct nvdimm_drvdata *ndd,
					   struct nd_namespace_label *nd_label,
					   u64 cookie)
{
	/*
	 * Let the EFI and CXL validation comingle, where fields that
	 * don't matter to CXL always validate.
	 */
	if (ndd->cxl)
		return true;
	return cookie == __le64_to_cpu(nd_label->efi.isetcookie);
}

static inline u16 nsl_get_position(struct nvdimm_drvdata *ndd,
				   struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return __le16_to_cpu(nd_label->cxl.position);
	return __le16_to_cpu(nd_label->efi.position);
}

static inline void nsl_set_position(struct nvdimm_drvdata *ndd,
				    struct nd_namespace_label *nd_label,
				    u16 position)
{
	if (ndd->cxl)
		nd_label->cxl.position = __cpu_to_le16(position);
	else
		nd_label->efi.position = __cpu_to_le16(position);
}

static inline u16 nsl_get_nlabel(struct nvdimm_drvdata *ndd,
				 struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return 0;
	return __le16_to_cpu(nd_label->efi.nlabel);
}

static inline void nsl_set_nlabel(struct nvdimm_drvdata *ndd,
				  struct nd_namespace_label *nd_label,
				  u16 nlabel)
{
	if (!ndd->cxl)
		nd_label->efi.nlabel = __cpu_to_le16(nlabel);
}

static inline u16 nsl_get_nrange(struct nvdimm_drvdata *ndd,
				 struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return __le16_to_cpu(nd_label->cxl.nrange);
	return 1;
}

static inline void nsl_set_nrange(struct nvdimm_drvdata *ndd,
				  struct nd_namespace_label *nd_label,
				  u16 nrange)
{
	if (ndd->cxl)
		nd_label->cxl.nrange = __cpu_to_le16(nrange);
}

static inline u64 nsl_get_lbasize(struct nvdimm_drvdata *ndd,
				  struct nd_namespace_label *nd_label)
{
	/*
	 * Yes, for some reason the EFI labels convey a massive 64-bit
	 * lbasize, that got fixed for CXL.
	 */
	if (ndd->cxl)
		return __le16_to_cpu(nd_label->cxl.lbasize);
	return __le64_to_cpu(nd_label->efi.lbasize);
}

static inline void nsl_set_lbasize(struct nvdimm_drvdata *ndd,
				   struct nd_namespace_label *nd_label,
				   u64 lbasize)
{
	if (ndd->cxl)
		nd_label->cxl.lbasize = __cpu_to_le16(lbasize);
	else
		nd_label->efi.lbasize = __cpu_to_le64(lbasize);
}

static inline const uuid_t *nsl_get_uuid(struct nvdimm_drvdata *ndd,
					 struct nd_namespace_label *nd_label,
					 uuid_t *uuid)
{
	if (ndd->cxl)
		import_uuid(uuid, nd_label->cxl.uuid);
	else
		import_uuid(uuid, nd_label->efi.uuid);
	return uuid;
}

static inline const uuid_t *nsl_set_uuid(struct nvdimm_drvdata *ndd,
					 struct nd_namespace_label *nd_label,
					 const uuid_t *uuid)
{
	if (ndd->cxl)
		export_uuid(nd_label->cxl.uuid, uuid);
	else
		export_uuid(nd_label->efi.uuid, uuid);
	return uuid;
}

static inline bool nsl_uuid_equal(struct nvdimm_drvdata *ndd,
				  struct nd_namespace_label *nd_label,
				  const uuid_t *uuid)
{
	uuid_t tmp;

	if (ndd->cxl)
		import_uuid(&tmp, nd_label->cxl.uuid);
	else
		import_uuid(&tmp, nd_label->efi.uuid);
	return uuid_equal(&tmp, uuid);
}

static inline const u8 *nsl_uuid_raw(struct nvdimm_drvdata *ndd,
				     struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return nd_label->cxl.uuid;
	return nd_label->efi.uuid;
}

bool nsl_validate_type_guid(struct nvdimm_drvdata *ndd,
			    struct nd_namespace_label *nd_label, guid_t *guid);
enum nvdimm_claim_class nsl_get_claim_class(struct nvdimm_drvdata *ndd,
					    struct nd_namespace_label *nd_label);

struct nd_region_data {
	int ns_count;
	int ns_active;
	unsigned int hints_shift;
	void __iomem *flush_wpq[];
};

static inline void __iomem *ndrd_get_flush_wpq(struct nd_region_data *ndrd,
		int dimm, int hint)
{
	unsigned int num = 1 << ndrd->hints_shift;
	unsigned int mask = num - 1;

	return ndrd->flush_wpq[dimm * num + (hint & mask)];
}

static inline void ndrd_set_flush_wpq(struct nd_region_data *ndrd, int dimm,
		int hint, void __iomem *flush)
{
	unsigned int num = 1 << ndrd->hints_shift;
	unsigned int mask = num - 1;

	ndrd->flush_wpq[dimm * num + (hint & mask)] = flush;
}

static inline struct nd_namespace_index *to_namespace_index(
		struct nvdimm_drvdata *ndd, int i)
{
	if (i < 0)
		return NULL;

	return ndd->data + sizeof_namespace_index(ndd) * i;
}

static inline struct nd_namespace_index *to_current_namespace_index(
		struct nvdimm_drvdata *ndd)
{
	return to_namespace_index(ndd, ndd->ns_current);
}

static inline struct nd_namespace_index *to_next_namespace_index(
		struct nvdimm_drvdata *ndd)
{
	return to_namespace_index(ndd, ndd->ns_next);
}

unsigned sizeof_namespace_label(struct nvdimm_drvdata *ndd);

#define efi_namespace_label_has(ndd, field) \
	(!ndd->cxl && offsetof(struct nvdimm_efi_label, field) \
		< sizeof_namespace_label(ndd))

#define nd_dbg_dpa(r, d, res, fmt, arg...) \
	dev_dbg((r) ? &(r)->dev : (d)->dev, "%s: %.13s: %#llx @ %#llx " fmt, \
		(r) ? dev_name((d)->dev) : "", res ? res->name : "null", \
		(unsigned long long) (res ? resource_size(res) : 0), \
		(unsigned long long) (res ? res->start : 0), ##arg)

#define for_each_dpa_resource(ndd, res) \
	for (res = (ndd)->dpa.child; res; res = res->sibling)

#define for_each_dpa_resource_safe(ndd, res, next) \
	for (res = (ndd)->dpa.child, next = res ? res->sibling : NULL; \
			res; res = next, next = next ? next->sibling : NULL)

struct nd_percpu_lane {
	int count;
	spinlock_t lock;
};

enum nd_label_flags {
	ND_LABEL_REAP,
};
struct nd_label_ent {
	struct list_head list;
	unsigned long flags;
	struct nd_namespace_label *label;
};

enum nd_mapping_lock_class {
	ND_MAPPING_CLASS0,
	ND_MAPPING_UUID_SCAN,
};

struct nd_mapping {
	struct nvdimm *nvdimm;
	u64 start;
	u64 size;
	int position;
	struct list_head labels;
	struct mutex lock;
	/*
	 * @ndd is for private use at region enable / disable time for
	 * get_ndd() + put_ndd(), all other nd_mapping to ndd
	 * conversions use to_ndd() which respects enabled state of the
	 * nvdimm.
	 */
	struct nvdimm_drvdata *ndd;
};

struct nd_region {
	struct device dev;
	struct ida ns_ida;
	struct ida btt_ida;
	struct ida pfn_ida;
	struct ida dax_ida;
	unsigned long flags;
	struct device *ns_seed;
	struct device *btt_seed;
	struct device *pfn_seed;
	struct device *dax_seed;
	unsigned long align;
	u16 ndr_mappings;
	u64 ndr_size;
	u64 ndr_start;
	int id, num_lanes, ro, numa_node, target_node;
	void *provider_data;
	struct kernfs_node *bb_state;
	struct badblocks bb;
	struct nd_interleave_set *nd_set;
	struct nd_percpu_lane __percpu *lane;
	int (*flush)(struct nd_region *nd_region, struct bio *bio);
	struct nd_mapping mapping[] __counted_by(ndr_mappings);
};

static inline bool nsl_validate_nlabel(struct nd_region *nd_region,
				       struct nvdimm_drvdata *ndd,
				       struct nd_namespace_label *nd_label)
{
	if (ndd->cxl)
		return true;
	return nsl_get_nlabel(ndd, nd_label) == nd_region->ndr_mappings;
}

/*
 * Lookup next in the repeating sequence of 01, 10, and 11.
 */
static inline unsigned nd_inc_seq(unsigned seq)
{
	static const unsigned next[] = { 0, 2, 3, 1 };

	return next[seq & 3];
}

struct btt;
struct nd_btt {
	struct device dev;
	struct nd_namespace_common *ndns;
	struct btt *btt;
	unsigned long lbasize;
	u64 size;
	uuid_t *uuid;
	int id;
	int initial_offset;
	u16 version_major;
	u16 version_minor;
};

enum nd_pfn_mode {
	PFN_MODE_NONE,
	PFN_MODE_RAM,
	PFN_MODE_PMEM,
};

struct nd_pfn {
	int id;
	uuid_t *uuid;
	struct device dev;
	unsigned long align;
	unsigned long npfns;
	enum nd_pfn_mode mode;
	struct nd_pfn_sb *pfn_sb;
	struct nd_namespace_common *ndns;
};

struct nd_dax {
	struct nd_pfn nd_pfn;
};

static inline u32 nd_info_block_reserve(void)
{
	return ALIGN(SZ_8K, PAGE_SIZE);
}

enum nd_async_mode {
	ND_SYNC,
	ND_ASYNC,
};

int nd_integrity_init(struct gendisk *disk, unsigned long meta_size);
void wait_nvdimm_bus_probe_idle(struct device *dev);
void nd_device_register(struct device *dev);
void nd_device_unregister(struct device *dev, enum nd_async_mode mode);
void nd_device_notify(struct device *dev, enum nvdimm_event event);
int nd_uuid_store(struct device *dev, uuid_t **uuid_out, const char *buf,
		size_t len);
ssize_t nd_size_select_show(unsigned long current_size,
		const unsigned long *supported, char *buf);
ssize_t nd_size_select_store(struct device *dev, const char *buf,
		unsigned long *current_size, const unsigned long *supported);
int __init nvdimm_init(void);
int __init nd_region_init(void);
int __init nd_label_init(void);
void nvdimm_exit(void);
void nd_region_exit(void);
struct nvdimm;
extern const struct attribute_group nd_device_attribute_group;
extern const struct attribute_group nd_numa_attribute_group;
extern const struct attribute_group *nvdimm_bus_attribute_groups[];
struct nvdimm_drvdata *to_ndd(struct nd_mapping *nd_mapping);
int nvdimm_check_config_data(struct device *dev);
int nvdimm_init_nsarea(struct nvdimm_drvdata *ndd);
int nvdimm_init_config_data(struct nvdimm_drvdata *ndd);
int nvdimm_get_config_data(struct nvdimm_drvdata *ndd, void *buf,
			   size_t offset, size_t len);
int nvdimm_set_config_data(struct nvdimm_drvdata *ndd, size_t offset,
		void *buf, size_t len);
long nvdimm_clear_poison(struct device *dev, phys_addr_t phys,
		unsigned int len);
void nvdimm_set_labeling(struct device *dev);
void nvdimm_set_locked(struct device *dev);
void nvdimm_clear_locked(struct device *dev);
int nvdimm_security_setup_events(struct device *dev);
#if IS_ENABLED(CONFIG_NVDIMM_KEYS)
int nvdimm_security_unlock(struct device *dev);
#else
static inline int nvdimm_security_unlock(struct device *dev)
{
	return 0;
}
#endif
struct nd_btt *to_nd_btt(struct device *dev);

struct nd_gen_sb {
	char reserved[SZ_4K - 8];
	__le64 checksum;
};

u64 nd_sb_checksum(struct nd_gen_sb *sb);
#if IS_ENABLED(CONFIG_BTT)
int nd_btt_probe(struct device *dev, struct nd_namespace_common *ndns);
bool is_nd_btt(struct device *dev);
struct device *nd_btt_create(struct nd_region *nd_region);
#else
static inline int nd_btt_probe(struct device *dev,
		struct nd_namespace_common *ndns)
{
	return -ENODEV;
}

static inline bool is_nd_btt(struct device *dev)
{
	return false;
}

static inline struct device *nd_btt_create(struct nd_region *nd_region)
{
	return NULL;
}
#endif

struct nd_pfn *to_nd_pfn(struct device *dev);
#if IS_ENABLED(CONFIG_NVDIMM_PFN)

#define MAX_NVDIMM_ALIGN	4

int nd_pfn_probe(struct device *dev, struct nd_namespace_common *ndns);
bool is_nd_pfn(struct device *dev);
struct device *nd_pfn_create(struct nd_region *nd_region);
struct device *nd_pfn_devinit(struct nd_pfn *nd_pfn,
		struct nd_namespace_common *ndns);
int nd_pfn_validate(struct nd_pfn *nd_pfn, const char *sig);
extern const struct attribute_group *nd_pfn_attribute_groups[];
#else
static inline int nd_pfn_probe(struct device *dev,
		struct nd_namespace_common *ndns)
{
	return -ENODEV;
}

static inline bool is_nd_pfn(struct device *dev)
{
	return false;
}

static inline struct device *nd_pfn_create(struct nd_region *nd_region)
{
	return NULL;
}

static inline int nd_pfn_validate(struct nd_pfn *nd_pfn, const char *sig)
{
	return -ENODEV;
}
#endif

struct nd_dax *to_nd_dax(struct device *dev);
#if IS_ENABLED(CONFIG_NVDIMM_DAX)
int nd_dax_probe(struct device *dev, struct nd_namespace_common *ndns);
bool is_nd_dax(const struct device *dev);
struct device *nd_dax_create(struct nd_region *nd_region);
static inline struct device *nd_dax_devinit(struct nd_dax *nd_dax,
					    struct nd_namespace_common *ndns)
{
	if (!nd_dax)
		return NULL;
	return nd_pfn_devinit(&nd_dax->nd_pfn, ndns);
}
#else
static inline int nd_dax_probe(struct device *dev,
		struct nd_namespace_common *ndns)
{
	return -ENODEV;
}

static inline bool is_nd_dax(const struct device *dev)
{
	return false;
}

static inline struct device *nd_dax_create(struct nd_region *nd_region)
{
	return NULL;
}
#endif

int nd_region_to_nstype(struct nd_region *nd_region);
int nd_region_register_namespaces(struct nd_region *nd_region, int *err);
u64 nd_region_interleave_set_cookie(struct nd_region *nd_region,
		struct nd_namespace_index *nsindex);
u64 nd_region_interleave_set_altcookie(struct nd_region *nd_region);
void nvdimm_bus_lock(struct device *dev);
void nvdimm_bus_unlock(struct device *dev);
bool is_nvdimm_bus_locked(struct device *dev);
void nvdimm_check_and_set_ro(struct gendisk *disk);
void nvdimm_drvdata_release(struct kref *kref);
void put_ndd(struct nvdimm_drvdata *ndd);
int nd_label_reserve_dpa(struct nvdimm_drvdata *ndd);
void nvdimm_free_dpa(struct nvdimm_drvdata *ndd, struct resource *res);
struct resource *nvdimm_allocate_dpa(struct nvdimm_drvdata *ndd,
		struct nd_label_id *label_id, resource_size_t start,
		resource_size_t n);
resource_size_t nvdimm_namespace_capacity(struct nd_namespace_common *ndns);
bool nvdimm_namespace_locked(struct nd_namespace_common *ndns);
struct nd_namespace_common *nvdimm_namespace_common_probe(struct device *dev);
int nvdimm_namespace_attach_btt(struct nd_namespace_common *ndns);
int nvdimm_namespace_detach_btt(struct nd_btt *nd_btt);
const char *nvdimm_namespace_disk_name(struct nd_namespace_common *ndns,
		char *name);
unsigned int pmem_sector_size(struct nd_namespace_common *ndns);
struct range;
void nvdimm_badblocks_populate(struct nd_region *nd_region,
		struct badblocks *bb, const struct range *range);
int devm_namespace_enable(struct device *dev, struct nd_namespace_common *ndns,
		resource_size_t size);
void devm_namespace_disable(struct device *dev,
		struct nd_namespace_common *ndns);
#if IS_ENABLED(CONFIG_ND_CLAIM)
/* max struct page size independent of kernel config */
#define MAX_STRUCT_PAGE_SIZE 64
int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pgmap);
#else
static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
				   struct dev_pagemap *pgmap)
{
	return -ENXIO;
}
#endif
int nd_region_activate(struct nd_region *nd_region);
static inline bool is_bad_pmem(struct badblocks *bb, sector_t sector,
		unsigned int len)
{
	if (bb->count) {
		sector_t first_bad;
		int num_bad;

		return !!badblocks_check(bb, sector, len / 512, &first_bad,
				&num_bad);
	}

	return false;
}
const uuid_t *nd_dev_to_uuid(struct device *dev);
bool pmem_should_map_pages(struct device *dev);
#endif /* __ND_H__ */
