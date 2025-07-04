// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(C) 2015-2018 Linaro Limited.
 *
 * Author: Tor Jeremiassen <tor@ti.com>
 * Author: Mathieu Poirier <mathieu.poirier@linaro.org>
 */

#include <linux/kernel.h>
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/coresight-pmu.h>
#include <linux/err.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <linux/zalloc.h>

#include <stdlib.h>

#include "auxtrace.h"
#include "color.h"
#include "cs-etm.h"
#include "cs-etm-decoder/cs-etm-decoder.h"
#include "debug.h"
#include "dso.h"
#include "evlist.h"
#include "intlist.h"
#include "machine.h"
#include "map.h"
#include "perf.h"
#include "session.h"
#include "map_symbol.h"
#include "branch.h"
#include "symbol.h"
#include "tool.h"
#include "thread.h"
#include "thread-stack.h"
#include "tsc.h"
#include <tools/libc_compat.h>
#include "util/synthetic-events.h"
#include "util/util.h"

struct cs_etm_auxtrace {
	struct auxtrace auxtrace;
	struct auxtrace_queues queues;
	struct auxtrace_heap heap;
	struct itrace_synth_opts synth_opts;
	struct perf_session *session;
	struct perf_tsc_conversion tc;

	/*
	 * Timeless has no timestamps in the trace so overlapping mmap lookups
	 * are less accurate but produces smaller trace data. We use context IDs
	 * in the trace instead of matching timestamps with fork records so
	 * they're not really needed in the general case. Overlapping mmaps
	 * happen in cases like between a fork and an exec.
	 */
	bool timeless_decoding;

	/*
	 * Per-thread ignores the trace channel ID and instead assumes that
	 * everything in a buffer comes from the same process regardless of
	 * which CPU it ran on. It also implies no context IDs so the TID is
	 * taken from the auxtrace buffer.
	 */
	bool per_thread_decoding;
	bool snapshot_mode;
	bool data_queued;
	bool has_virtual_ts; /* Virtual/Kernel timestamps in the trace. */

	int num_cpu;
	u64 latest_kernel_timestamp;
	u32 auxtrace_type;
	u64 branches_sample_type;
	u64 branches_id;
	u64 instructions_sample_type;
	u64 instructions_sample_period;
	u64 instructions_id;
	u64 **metadata;
	unsigned int pmu_type;
	enum cs_etm_pid_fmt pid_fmt;
};

struct cs_etm_traceid_queue {
	u8 trace_chan_id;
	u64 period_instructions;
	size_t last_branch_pos;
	union perf_event *event_buf;
	struct thread *thread;
	struct thread *prev_packet_thread;
	ocsd_ex_level prev_packet_el;
	ocsd_ex_level el;
	struct branch_stack *last_branch;
	struct branch_stack *last_branch_rb;
	struct cs_etm_packet *prev_packet;
	struct cs_etm_packet *packet;
	struct cs_etm_packet_queue packet_queue;
};

struct cs_etm_queue {
	struct cs_etm_auxtrace *etm;
	struct cs_etm_decoder *decoder;
	struct auxtrace_buffer *buffer;
	unsigned int queue_nr;
	u8 pending_timestamp_chan_id;
	u64 offset;
	const unsigned char *buf;
	size_t buf_len, buf_used;
	/* Conversion between traceID and index in traceid_queues array */
	struct intlist *traceid_queues_list;
	struct cs_etm_traceid_queue **traceid_queues;
};

/* RB tree for quick conversion between traceID and metadata pointers */
static struct intlist *traceid_list;

static int cs_etm__process_timestamped_queues(struct cs_etm_auxtrace *etm);
static int cs_etm__process_timeless_queues(struct cs_etm_auxtrace *etm,
					   pid_t tid);
static int cs_etm__get_data_block(struct cs_etm_queue *etmq);
static int cs_etm__decode_data_block(struct cs_etm_queue *etmq);

/* PTMs ETMIDR [11:8] set to b0011 */
#define ETMIDR_PTM_VERSION 0x00000300

/*
 * A struct auxtrace_heap_item only has a queue_nr and a timestamp to
 * work with.  One option is to modify to auxtrace_heap_XYZ() API or simply
 * encode the etm queue number as the upper 16 bit and the channel as
 * the lower 16 bit.
 */
#define TO_CS_QUEUE_NR(queue_nr, trace_chan_id)	\
		      (queue_nr << 16 | trace_chan_id)
#define TO_QUEUE_NR(cs_queue_nr) (cs_queue_nr >> 16)
#define TO_TRACE_CHAN_ID(cs_queue_nr) (cs_queue_nr & 0x0000ffff)

static u32 cs_etm__get_v7_protocol_version(u32 etmidr)
{
	etmidr &= ETMIDR_PTM_VERSION;

	if (etmidr == ETMIDR_PTM_VERSION)
		return CS_ETM_PROTO_PTM;

	return CS_ETM_PROTO_ETMV3;
}

static int cs_etm__get_magic(u8 trace_chan_id, u64 *magic)
{
	struct int_node *inode;
	u64 *metadata;

	inode = intlist__find(traceid_list, trace_chan_id);
	if (!inode)
		return -EINVAL;

	metadata = inode->priv;
	*magic = metadata[CS_ETM_MAGIC];
	return 0;
}

int cs_etm__get_cpu(u8 trace_chan_id, int *cpu)
{
	struct int_node *inode;
	u64 *metadata;

	inode = intlist__find(traceid_list, trace_chan_id);
	if (!inode)
		return -EINVAL;

	metadata = inode->priv;
	*cpu = (int)metadata[CS_ETM_CPU];
	return 0;
}

/*
 * The returned PID format is presented as an enum:
 *
 *   CS_ETM_PIDFMT_CTXTID: CONTEXTIDR or CONTEXTIDR_EL1 is traced.
 *   CS_ETM_PIDFMT_CTXTID2: CONTEXTIDR_EL2 is traced.
 *   CS_ETM_PIDFMT_NONE: No context IDs
 *
 * It's possible that the two bits ETM_OPT_CTXTID and ETM_OPT_CTXTID2
 * are enabled at the same time when the session runs on an EL2 kernel.
 * This means the CONTEXTIDR_EL1 and CONTEXTIDR_EL2 both will be
 * recorded in the trace data, the tool will selectively use
 * CONTEXTIDR_EL2 as PID.
 *
 * The result is cached in etm->pid_fmt so this function only needs to be called
 * when processing the aux info.
 */
static enum cs_etm_pid_fmt cs_etm__init_pid_fmt(u64 *metadata)
{
	u64 val;

	if (metadata[CS_ETM_MAGIC] == __perf_cs_etmv3_magic) {
		val = metadata[CS_ETM_ETMCR];
		/* CONTEXTIDR is traced */
		if (val & BIT(ETM_OPT_CTXTID))
			return CS_ETM_PIDFMT_CTXTID;
	} else {
		val = metadata[CS_ETMV4_TRCCONFIGR];
		/* CONTEXTIDR_EL2 is traced */
		if (val & (BIT(ETM4_CFG_BIT_VMID) | BIT(ETM4_CFG_BIT_VMID_OPT)))
			return CS_ETM_PIDFMT_CTXTID2;
		/* CONTEXTIDR_EL1 is traced */
		else if (val & BIT(ETM4_CFG_BIT_CTXTID))
			return CS_ETM_PIDFMT_CTXTID;
	}

	return CS_ETM_PIDFMT_NONE;
}

enum cs_etm_pid_fmt cs_etm__get_pid_fmt(struct cs_etm_queue *etmq)
{
	return etmq->etm->pid_fmt;
}

static int cs_etm__map_trace_id(u8 trace_chan_id, u64 *cpu_metadata)
{
	struct int_node *inode;

	/* Get an RB node for this CPU */
	inode = intlist__findnew(traceid_list, trace_chan_id);

	/* Something went wrong, no need to continue */
	if (!inode)
		return -ENOMEM;

	/*
	 * The node for that CPU should not be taken.
	 * Back out if that's the case.
	 */
	if (inode->priv)
		return -EINVAL;

	/* All good, associate the traceID with the metadata pointer */
	inode->priv = cpu_metadata;

	return 0;
}

static int cs_etm__metadata_get_trace_id(u8 *trace_chan_id, u64 *cpu_metadata)
{
	u64 cs_etm_magic = cpu_metadata[CS_ETM_MAGIC];

	switch (cs_etm_magic) {
	case __perf_cs_etmv3_magic:
		*trace_chan_id = (u8)(cpu_metadata[CS_ETM_ETMTRACEIDR] &
				      CORESIGHT_TRACE_ID_VAL_MASK);
		break;
	case __perf_cs_etmv4_magic:
	case __perf_cs_ete_magic:
		*trace_chan_id = (u8)(cpu_metadata[CS_ETMV4_TRCTRACEIDR] &
				      CORESIGHT_TRACE_ID_VAL_MASK);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * update metadata trace ID from the value found in the AUX_HW_INFO packet.
 * This will also clear the CORESIGHT_TRACE_ID_UNUSED_FLAG flag if present.
 */
static int cs_etm__metadata_set_trace_id(u8 trace_chan_id, u64 *cpu_metadata)
{
	u64 cs_etm_magic = cpu_metadata[CS_ETM_MAGIC];

	switch (cs_etm_magic) {
	case __perf_cs_etmv3_magic:
		 cpu_metadata[CS_ETM_ETMTRACEIDR] = trace_chan_id;
		break;
	case __perf_cs_etmv4_magic:
	case __perf_cs_ete_magic:
		cpu_metadata[CS_ETMV4_TRCTRACEIDR] = trace_chan_id;
		break;

	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * Get a metadata index for a specific cpu from an array.
 *
 */
static int get_cpu_data_idx(struct cs_etm_auxtrace *etm, int cpu)
{
	int i;

	for (i = 0; i < etm->num_cpu; i++) {
		if (etm->metadata[i][CS_ETM_CPU] == (u64)cpu) {
			return i;
		}
	}

	return -1;
}

/*
 * Get a metadata for a specific cpu from an array.
 *
 */
static u64 *get_cpu_data(struct cs_etm_auxtrace *etm, int cpu)
{
	int idx = get_cpu_data_idx(etm, cpu);

	return (idx != -1) ? etm->metadata[idx] : NULL;
}

/*
 * Handle the PERF_RECORD_AUX_OUTPUT_HW_ID event.
 *
 * The payload associates the Trace ID and the CPU.
 * The routine is tolerant of seeing multiple packets with the same association,
 * but a CPU / Trace ID association changing during a session is an error.
 */
static int cs_etm__process_aux_output_hw_id(struct perf_session *session,
					    union perf_event *event)
{
	struct cs_etm_auxtrace *etm;
	struct perf_sample sample;
	struct int_node *inode;
	struct evsel *evsel;
	u64 *cpu_data;
	u64 hw_id;
	int cpu, version, err;
	u8 trace_chan_id, curr_chan_id;

	/* extract and parse the HW ID */
	hw_id = event->aux_output_hw_id.hw_id;
	version = FIELD_GET(CS_AUX_HW_ID_VERSION_MASK, hw_id);
	trace_chan_id = FIELD_GET(CS_AUX_HW_ID_TRACE_ID_MASK, hw_id);

	/* check that we can handle this version */
	if (version > CS_AUX_HW_ID_CURR_VERSION)
		return -EINVAL;

	/* get access to the etm metadata */
	etm = container_of(session->auxtrace, struct cs_etm_auxtrace, auxtrace);
	if (!etm || !etm->metadata)
		return -EINVAL;

	/* parse the sample to get the CPU */
	evsel = evlist__event2evsel(session->evlist, event);
	if (!evsel)
		return -EINVAL;
	err = evsel__parse_sample(evsel, event, &sample);
	if (err)
		return err;
	cpu = sample.cpu;
	if (cpu == -1) {
		/* no CPU in the sample - possibly recorded with an old version of perf */
		pr_err("CS_ETM: no CPU AUX_OUTPUT_HW_ID sample. Use compatible perf to record.");
		return -EINVAL;
	}

	/* See if the ID is mapped to a CPU, and it matches the current CPU */
	inode = intlist__find(traceid_list, trace_chan_id);
	if (inode) {
		cpu_data = inode->priv;
		if ((int)cpu_data[CS_ETM_CPU] != cpu) {
			pr_err("CS_ETM: map mismatch between HW_ID packet CPU and Trace ID\n");
			return -EINVAL;
		}

		/* check that the mapped ID matches */
		err = cs_etm__metadata_get_trace_id(&curr_chan_id, cpu_data);
		if (err)
			return err;
		if (curr_chan_id != trace_chan_id) {
			pr_err("CS_ETM: mismatch between CPU trace ID and HW_ID packet ID\n");
			return -EINVAL;
		}

		/* mapped and matched - return OK */
		return 0;
	}

	cpu_data = get_cpu_data(etm, cpu);
	if (cpu_data == NULL)
		return err;

	/* not one we've seen before - lets map it */
	err = cs_etm__map_trace_id(trace_chan_id, cpu_data);
	if (err)
		return err;

	/*
	 * if we are picking up the association from the packet, need to plug
	 * the correct trace ID into the metadata for setting up decoders later.
	 */
	err = cs_etm__metadata_set_trace_id(trace_chan_id, cpu_data);
	return err;
}

void cs_etm__etmq_set_traceid_queue_timestamp(struct cs_etm_queue *etmq,
					      u8 trace_chan_id)
{
	/*
	 * When a timestamp packet is encountered the backend code
	 * is stopped so that the front end has time to process packets
	 * that were accumulated in the traceID queue.  Since there can
	 * be more than one channel per cs_etm_queue, we need to specify
	 * what traceID queue needs servicing.
	 */
	etmq->pending_timestamp_chan_id = trace_chan_id;
}

static u64 cs_etm__etmq_get_timestamp(struct cs_etm_queue *etmq,
				      u8 *trace_chan_id)
{
	struct cs_etm_packet_queue *packet_queue;

	if (!etmq->pending_timestamp_chan_id)
		return 0;

	if (trace_chan_id)
		*trace_chan_id = etmq->pending_timestamp_chan_id;

	packet_queue = cs_etm__etmq_get_packet_queue(etmq,
						     etmq->pending_timestamp_chan_id);
	if (!packet_queue)
		return 0;

	/* Acknowledge pending status */
	etmq->pending_timestamp_chan_id = 0;

	/* See function cs_etm_decoder__do_{hard|soft}_timestamp() */
	return packet_queue->cs_timestamp;
}

static void cs_etm__clear_packet_queue(struct cs_etm_packet_queue *queue)
{
	int i;

	queue->head = 0;
	queue->tail = 0;
	queue->packet_count = 0;
	for (i = 0; i < CS_ETM_PACKET_MAX_BUFFER; i++) {
		queue->packet_buffer[i].isa = CS_ETM_ISA_UNKNOWN;
		queue->packet_buffer[i].start_addr = CS_ETM_INVAL_ADDR;
		queue->packet_buffer[i].end_addr = CS_ETM_INVAL_ADDR;
		queue->packet_buffer[i].instr_count = 0;
		queue->packet_buffer[i].last_instr_taken_branch = false;
		queue->packet_buffer[i].last_instr_size = 0;
		queue->packet_buffer[i].last_instr_type = 0;
		queue->packet_buffer[i].last_instr_subtype = 0;
		queue->packet_buffer[i].last_instr_cond = 0;
		queue->packet_buffer[i].flags = 0;
		queue->packet_buffer[i].exception_number = UINT32_MAX;
		queue->packet_buffer[i].trace_chan_id = UINT8_MAX;
		queue->packet_buffer[i].cpu = INT_MIN;
	}
}

static void cs_etm__clear_all_packet_queues(struct cs_etm_queue *etmq)
{
	int idx;
	struct int_node *inode;
	struct cs_etm_traceid_queue *tidq;
	struct intlist *traceid_queues_list = etmq->traceid_queues_list;

	intlist__for_each_entry(inode, traceid_queues_list) {
		idx = (int)(intptr_t)inode->priv;
		tidq = etmq->traceid_queues[idx];
		cs_etm__clear_packet_queue(&tidq->packet_queue);
	}
}

static int cs_etm__init_traceid_queue(struct cs_etm_queue *etmq,
				      struct cs_etm_traceid_queue *tidq,
				      u8 trace_chan_id)
{
	int rc = -ENOMEM;
	struct auxtrace_queue *queue;
	struct cs_etm_auxtrace *etm = etmq->etm;

	cs_etm__clear_packet_queue(&tidq->packet_queue);

	queue = &etmq->etm->queues.queue_array[etmq->queue_nr];
	tidq->trace_chan_id = trace_chan_id;
	tidq->el = tidq->prev_packet_el = ocsd_EL_unknown;
	tidq->thread = machine__findnew_thread(&etm->session->machines.host, -1,
					       queue->tid);
	tidq->prev_packet_thread = machine__idle_thread(&etm->session->machines.host);

	tidq->packet = zalloc(sizeof(struct cs_etm_packet));
	if (!tidq->packet)
		goto out;

	tidq->prev_packet = zalloc(sizeof(struct cs_etm_packet));
	if (!tidq->prev_packet)
		goto out_free;

	if (etm->synth_opts.last_branch) {
		size_t sz = sizeof(struct branch_stack);

		sz += etm->synth_opts.last_branch_sz *
		      sizeof(struct branch_entry);
		tidq->last_branch = zalloc(sz);
		if (!tidq->last_branch)
			goto out_free;
		tidq->last_branch_rb = zalloc(sz);
		if (!tidq->last_branch_rb)
			goto out_free;
	}

	tidq->event_buf = malloc(PERF_SAMPLE_MAX_SIZE);
	if (!tidq->event_buf)
		goto out_free;

	return 0;

out_free:
	zfree(&tidq->last_branch_rb);
	zfree(&tidq->last_branch);
	zfree(&tidq->prev_packet);
	zfree(&tidq->packet);
out:
	return rc;
}

static struct cs_etm_traceid_queue
*cs_etm__etmq_get_traceid_queue(struct cs_etm_queue *etmq, u8 trace_chan_id)
{
	int idx;
	struct int_node *inode;
	struct intlist *traceid_queues_list;
	struct cs_etm_traceid_queue *tidq, **traceid_queues;
	struct cs_etm_auxtrace *etm = etmq->etm;

	if (etm->per_thread_decoding)
		trace_chan_id = CS_ETM_PER_THREAD_TRACEID;

	traceid_queues_list = etmq->traceid_queues_list;

	/*
	 * Check if the traceid_queue exist for this traceID by looking
	 * in the queue list.
	 */
	inode = intlist__find(traceid_queues_list, trace_chan_id);
	if (inode) {
		idx = (int)(intptr_t)inode->priv;
		return etmq->traceid_queues[idx];
	}

	/* We couldn't find a traceid_queue for this traceID, allocate one */
	tidq = malloc(sizeof(*tidq));
	if (!tidq)
		return NULL;

	memset(tidq, 0, sizeof(*tidq));

	/* Get a valid index for the new traceid_queue */
	idx = intlist__nr_entries(traceid_queues_list);
	/* Memory for the inode is free'ed in cs_etm_free_traceid_queues () */
	inode = intlist__findnew(traceid_queues_list, trace_chan_id);
	if (!inode)
		goto out_free;

	/* Associate this traceID with this index */
	inode->priv = (void *)(intptr_t)idx;

	if (cs_etm__init_traceid_queue(etmq, tidq, trace_chan_id))
		goto out_free;

	/* Grow the traceid_queues array by one unit */
	traceid_queues = etmq->traceid_queues;
	traceid_queues = reallocarray(traceid_queues,
				      idx + 1,
				      sizeof(*traceid_queues));

	/*
	 * On failure reallocarray() returns NULL and the original block of
	 * memory is left untouched.
	 */
	if (!traceid_queues)
		goto out_free;

	traceid_queues[idx] = tidq;
	etmq->traceid_queues = traceid_queues;

	return etmq->traceid_queues[idx];

out_free:
	/*
	 * Function intlist__remove() removes the inode from the list
	 * and delete the memory associated to it.
	 */
	intlist__remove(traceid_queues_list, inode);
	free(tidq);

	return NULL;
}

struct cs_etm_packet_queue
*cs_etm__etmq_get_packet_queue(struct cs_etm_queue *etmq, u8 trace_chan_id)
{
	struct cs_etm_traceid_queue *tidq;

	tidq = cs_etm__etmq_get_traceid_queue(etmq, trace_chan_id);
	if (tidq)
		return &tidq->packet_queue;

	return NULL;
}

static void cs_etm__packet_swap(struct cs_etm_auxtrace *etm,
				struct cs_etm_traceid_queue *tidq)
{
	struct cs_etm_packet *tmp;

	if (etm->synth_opts.branches || etm->synth_opts.last_branch ||
	    etm->synth_opts.instructions) {
		/*
		 * Swap PACKET with PREV_PACKET: PACKET becomes PREV_PACKET for
		 * the next incoming packet.
		 *
		 * Threads and exception levels are also tracked for both the
		 * previous and current packets. This is because the previous
		 * packet is used for the 'from' IP for branch samples, so the
		 * thread at that time must also be assigned to that sample.
		 * Across discontinuity packets the thread can change, so by
		 * tracking the thread for the previous packet the branch sample
		 * will have the correct info.
		 */
		tmp = tidq->packet;
		tidq->packet = tidq->prev_packet;
		tidq->prev_packet = tmp;
		tidq->prev_packet_el = tidq->el;
		thread__put(tidq->prev_packet_thread);
		tidq->prev_packet_thread = thread__get(tidq->thread);
	}
}

static void cs_etm__packet_dump(const char *pkt_string)
{
	const char *color = PERF_COLOR_BLUE;
	int len = strlen(pkt_string);

	if (len && (pkt_string[len-1] == '\n'))
		color_fprintf(stdout, color, "	%s", pkt_string);
	else
		color_fprintf(stdout, color, "	%s\n", pkt_string);

	fflush(stdout);
}

static void cs_etm__set_trace_param_etmv3(struct cs_etm_trace_params *t_params,
					  struct cs_etm_auxtrace *etm, int t_idx,
					  int m_idx, u32 etmidr)
{
	u64 **metadata = etm->metadata;

	t_params[t_idx].protocol = cs_etm__get_v7_protocol_version(etmidr);
	t_params[t_idx].etmv3.reg_ctrl = metadata[m_idx][CS_ETM_ETMCR];
	t_params[t_idx].etmv3.reg_trc_id = metadata[m_idx][CS_ETM_ETMTRACEIDR];
}

static void cs_etm__set_trace_param_etmv4(struct cs_etm_trace_params *t_params,
					  struct cs_etm_auxtrace *etm, int t_idx,
					  int m_idx)
{
	u64 **metadata = etm->metadata;

	t_params[t_idx].protocol = CS_ETM_PROTO_ETMV4i;
	t_params[t_idx].etmv4.reg_idr0 = metadata[m_idx][CS_ETMV4_TRCIDR0];
	t_params[t_idx].etmv4.reg_idr1 = metadata[m_idx][CS_ETMV4_TRCIDR1];
	t_params[t_idx].etmv4.reg_idr2 = metadata[m_idx][CS_ETMV4_TRCIDR2];
	t_params[t_idx].etmv4.reg_idr8 = metadata[m_idx][CS_ETMV4_TRCIDR8];
	t_params[t_idx].etmv4.reg_configr = metadata[m_idx][CS_ETMV4_TRCCONFIGR];
	t_params[t_idx].etmv4.reg_traceidr = metadata[m_idx][CS_ETMV4_TRCTRACEIDR];
}

static void cs_etm__set_trace_param_ete(struct cs_etm_trace_params *t_params,
					  struct cs_etm_auxtrace *etm, int t_idx,
					  int m_idx)
{
	u64 **metadata = etm->metadata;

	t_params[t_idx].protocol = CS_ETM_PROTO_ETE;
	t_params[t_idx].ete.reg_idr0 = metadata[m_idx][CS_ETE_TRCIDR0];
	t_params[t_idx].ete.reg_idr1 = metadata[m_idx][CS_ETE_TRCIDR1];
	t_params[t_idx].ete.reg_idr2 = metadata[m_idx][CS_ETE_TRCIDR2];
	t_params[t_idx].ete.reg_idr8 = metadata[m_idx][CS_ETE_TRCIDR8];
	t_params[t_idx].ete.reg_configr = metadata[m_idx][CS_ETE_TRCCONFIGR];
	t_params[t_idx].ete.reg_traceidr = metadata[m_idx][CS_ETE_TRCTRACEIDR];
	t_params[t_idx].ete.reg_devarch = metadata[m_idx][CS_ETE_TRCDEVARCH];
}

static int cs_etm__init_trace_params(struct cs_etm_trace_params *t_params,
				     struct cs_etm_auxtrace *etm,
				     bool formatted,
				     int sample_cpu,
				     int decoders)
{
	int t_idx, m_idx;
	u32 etmidr;
	u64 architecture;

	for (t_idx = 0; t_idx < decoders; t_idx++) {
		if (formatted)
			m_idx = t_idx;
		else {
			m_idx = get_cpu_data_idx(etm, sample_cpu);
			if (m_idx == -1) {
				pr_warning("CS_ETM: unknown CPU, falling back to first metadata\n");
				m_idx = 0;
			}
		}

		architecture = etm->metadata[m_idx][CS_ETM_MAGIC];

		switch (architecture) {
		case __perf_cs_etmv3_magic:
			etmidr = etm->metadata[m_idx][CS_ETM_ETMIDR];
			cs_etm__set_trace_param_etmv3(t_params, etm, t_idx, m_idx, etmidr);
			break;
		case __perf_cs_etmv4_magic:
			cs_etm__set_trace_param_etmv4(t_params, etm, t_idx, m_idx);
			break;
		case __perf_cs_ete_magic:
			cs_etm__set_trace_param_ete(t_params, etm, t_idx, m_idx);
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int cs_etm__init_decoder_params(struct cs_etm_decoder_params *d_params,
				       struct cs_etm_queue *etmq,
				       enum cs_etm_decoder_operation mode,
				       bool formatted)
{
	int ret = -EINVAL;

	if (!(mode < CS_ETM_OPERATION_MAX))
		goto out;

	d_params->packet_printer = cs_etm__packet_dump;
	d_params->operation = mode;
	d_params->data = etmq;
	d_params->formatted = formatted;
	d_params->fsyncs = false;
	d_params->hsyncs = false;
	d_params->frame_aligned = true;

	ret = 0;
out:
	return ret;
}

static void cs_etm__dump_event(struct cs_etm_queue *etmq,
			       struct auxtrace_buffer *buffer)
{
	int ret;
	const char *color = PERF_COLOR_BLUE;
	size_t buffer_used = 0;

	fprintf(stdout, "\n");
	color_fprintf(stdout, color,
		     ". ... CoreSight %s Trace data: size %#zx bytes\n",
		     cs_etm_decoder__get_name(etmq->decoder), buffer->size);

	do {
		size_t consumed;

		ret = cs_etm_decoder__process_data_block(
				etmq->decoder, buffer->offset,
				&((u8 *)buffer->data)[buffer_used],
				buffer->size - buffer_used, &consumed);
		if (ret)
			break;

		buffer_used += consumed;
	} while (buffer_used < buffer->size);

	cs_etm_decoder__reset(etmq->decoder);
}

static int cs_etm__flush_events(struct perf_session *session,
				struct perf_tool *tool)
{
	struct cs_etm_auxtrace *etm = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);
	if (dump_trace)
		return 0;

	if (!tool->ordered_events)
		return -EINVAL;

	if (etm->timeless_decoding) {
		/*
		 * Pass tid = -1 to process all queues. But likely they will have
		 * already been processed on PERF_RECORD_EXIT anyway.
		 */
		return cs_etm__process_timeless_queues(etm, -1);
	}

	return cs_etm__process_timestamped_queues(etm);
}

static void cs_etm__free_traceid_queues(struct cs_etm_queue *etmq)
{
	int idx;
	uintptr_t priv;
	struct int_node *inode, *tmp;
	struct cs_etm_traceid_queue *tidq;
	struct intlist *traceid_queues_list = etmq->traceid_queues_list;

	intlist__for_each_entry_safe(inode, tmp, traceid_queues_list) {
		priv = (uintptr_t)inode->priv;
		idx = priv;

		/* Free this traceid_queue from the array */
		tidq = etmq->traceid_queues[idx];
		thread__zput(tidq->thread);
		thread__zput(tidq->prev_packet_thread);
		zfree(&tidq->event_buf);
		zfree(&tidq->last_branch);
		zfree(&tidq->last_branch_rb);
		zfree(&tidq->prev_packet);
		zfree(&tidq->packet);
		zfree(&tidq);

		/*
		 * Function intlist__remove() removes the inode from the list
		 * and delete the memory associated to it.
		 */
		intlist__remove(traceid_queues_list, inode);
	}

	/* Then the RB tree itself */
	intlist__delete(traceid_queues_list);
	etmq->traceid_queues_list = NULL;

	/* finally free the traceid_queues array */
	zfree(&etmq->traceid_queues);
}

static void cs_etm__free_queue(void *priv)
{
	struct cs_etm_queue *etmq = priv;

	if (!etmq)
		return;

	cs_etm_decoder__free(etmq->decoder);
	cs_etm__free_traceid_queues(etmq);
	free(etmq);
}

static void cs_etm__free_events(struct perf_session *session)
{
	unsigned int i;
	struct cs_etm_auxtrace *aux = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);
	struct auxtrace_queues *queues = &aux->queues;

	for (i = 0; i < queues->nr_queues; i++) {
		cs_etm__free_queue(queues->queue_array[i].priv);
		queues->queue_array[i].priv = NULL;
	}

	auxtrace_queues__free(queues);
}

static void cs_etm__free(struct perf_session *session)
{
	int i;
	struct int_node *inode, *tmp;
	struct cs_etm_auxtrace *aux = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);
	cs_etm__free_events(session);
	session->auxtrace = NULL;

	/* First remove all traceID/metadata nodes for the RB tree */
	intlist__for_each_entry_safe(inode, tmp, traceid_list)
		intlist__remove(traceid_list, inode);
	/* Then the RB tree itself */
	intlist__delete(traceid_list);

	for (i = 0; i < aux->num_cpu; i++)
		zfree(&aux->metadata[i]);

	zfree(&aux->metadata);
	zfree(&aux);
}

static bool cs_etm__evsel_is_auxtrace(struct perf_session *session,
				      struct evsel *evsel)
{
	struct cs_etm_auxtrace *aux = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);

	return evsel->core.attr.type == aux->pmu_type;
}

static struct machine *cs_etm__get_machine(struct cs_etm_queue *etmq,
					   ocsd_ex_level el)
{
	enum cs_etm_pid_fmt pid_fmt = cs_etm__get_pid_fmt(etmq);

	/*
	 * For any virtualisation based on nVHE (e.g. pKVM), or host kernels
	 * running at EL1 assume everything is the host.
	 */
	if (pid_fmt == CS_ETM_PIDFMT_CTXTID)
		return &etmq->etm->session->machines.host;

	/*
	 * Not perfect, but otherwise assume anything in EL1 is the default
	 * guest, and everything else is the host. Distinguishing between guest
	 * and host userspaces isn't currently supported either. Neither is
	 * multiple guest support. All this does is reduce the likeliness of
	 * decode errors where we look into the host kernel maps when it should
	 * have been the guest maps.
	 */
	switch (el) {
	case ocsd_EL1:
		return machines__find_guest(&etmq->etm->session->machines,
					    DEFAULT_GUEST_KERNEL_ID);
	case ocsd_EL3:
	case ocsd_EL2:
	case ocsd_EL0:
	case ocsd_EL_unknown:
	default:
		return &etmq->etm->session->machines.host;
	}
}

static u8 cs_etm__cpu_mode(struct cs_etm_queue *etmq, u64 address,
			   ocsd_ex_level el)
{
	struct machine *machine = cs_etm__get_machine(etmq, el);

	if (address >= machine__kernel_start(machine)) {
		if (machine__is_host(machine))
			return PERF_RECORD_MISC_KERNEL;
		else
			return PERF_RECORD_MISC_GUEST_KERNEL;
	} else {
		if (machine__is_host(machine))
			return PERF_RECORD_MISC_USER;
		else {
			/*
			 * Can't really happen at the moment because
			 * cs_etm__get_machine() will always return
			 * machines.host for any non EL1 trace.
			 */
			return PERF_RECORD_MISC_GUEST_USER;
		}
	}
}

static u32 cs_etm__mem_access(struct cs_etm_queue *etmq, u8 trace_chan_id,
			      u64 address, size_t size, u8 *buffer,
			      const ocsd_mem_space_acc_t mem_space)
{
	u8  cpumode;
	u64 offset;
	int len;
	struct addr_location al;
	struct dso *dso;
	struct cs_etm_traceid_queue *tidq;
	int ret = 0;

	if (!etmq)
		return 0;

	addr_location__init(&al);
	tidq = cs_etm__etmq_get_traceid_queue(etmq, trace_chan_id);
	if (!tidq)
		goto out;

	/*
	 * We've already tracked EL along side the PID in cs_etm__set_thread()
	 * so double check that it matches what OpenCSD thinks as well. It
	 * doesn't distinguish between EL0 and EL1 for this mem access callback
	 * so we had to do the extra tracking. Skip validation if it's any of
	 * the 'any' values.
	 */
	if (!(mem_space == OCSD_MEM_SPACE_ANY ||
	      mem_space == OCSD_MEM_SPACE_N || mem_space == OCSD_MEM_SPACE_S)) {
		if (mem_space & OCSD_MEM_SPACE_EL1N) {
			/* Includes both non secure EL1 and EL0 */
			assert(tidq->el == ocsd_EL1 || tidq->el == ocsd_EL0);
		} else if (mem_space & OCSD_MEM_SPACE_EL2)
			assert(tidq->el == ocsd_EL2);
		else if (mem_space & OCSD_MEM_SPACE_EL3)
			assert(tidq->el == ocsd_EL3);
	}

	cpumode = cs_etm__cpu_mode(etmq, address, tidq->el);

	if (!thread__find_map(tidq->thread, cpumode, address, &al))
		goto out;

	dso = map__dso(al.map);
	if (!dso)
		goto out;

	if (dso->data.status == DSO_DATA_STATUS_ERROR &&
	    dso__data_status_seen(dso, DSO_DATA_STATUS_SEEN_ITRACE))
		goto out;

	offset = map__map_ip(al.map, address);

	map__load(al.map);

	len = dso__data_read_offset(dso, maps__machine(thread__maps(tidq->thread)),
				    offset, buffer, size);

	if (len <= 0) {
		ui__warning_once("CS ETM Trace: Missing DSO. Use 'perf archive' or debuginfod to export data from the traced system.\n"
				 "              Enable CONFIG_PROC_KCORE or use option '-k /path/to/vmlinux' for kernel symbols.\n");
		if (!dso->auxtrace_warned) {
			pr_err("CS ETM Trace: Debug data not found for address %#"PRIx64" in %s\n",
				    address,
				    dso->long_name ? dso->long_name : "Unknown");
			dso->auxtrace_warned = true;
		}
		goto out;
	}
	ret = len;
out:
	addr_location__exit(&al);
	return ret;
}

static struct cs_etm_queue *cs_etm__alloc_queue(struct cs_etm_auxtrace *etm,
						bool formatted, int sample_cpu)
{
	struct cs_etm_decoder_params d_params;
	struct cs_etm_trace_params  *t_params = NULL;
	struct cs_etm_queue *etmq;
	/*
	 * Each queue can only contain data from one CPU when unformatted, so only one decoder is
	 * needed.
	 */
	int decoders = formatted ? etm->num_cpu : 1;

	etmq = zalloc(sizeof(*etmq));
	if (!etmq)
		return NULL;

	etmq->traceid_queues_list = intlist__new(NULL);
	if (!etmq->traceid_queues_list)
		goto out_free;

	/* Use metadata to fill in trace parameters for trace decoder */
	t_params = zalloc(sizeof(*t_params) * decoders);

	if (!t_params)
		goto out_free;

	if (cs_etm__init_trace_params(t_params, etm, formatted, sample_cpu, decoders))
		goto out_free;

	/* Set decoder parameters to decode trace packets */
	if (cs_etm__init_decoder_params(&d_params, etmq,
					dump_trace ? CS_ETM_OPERATION_PRINT :
						     CS_ETM_OPERATION_DECODE,
					formatted))
		goto out_free;

	etmq->decoder = cs_etm_decoder__new(decoders, &d_params,
					    t_params);

	if (!etmq->decoder)
		goto out_free;

	/*
	 * Register a function to handle all memory accesses required by
	 * the trace decoder library.
	 */
	if (cs_etm_decoder__add_mem_access_cb(etmq->decoder,
					      0x0L, ((u64) -1L),
					      cs_etm__mem_access))
		goto out_free_decoder;

	zfree(&t_params);
	return etmq;

out_free_decoder:
	cs_etm_decoder__free(etmq->decoder);
out_free:
	intlist__delete(etmq->traceid_queues_list);
	free(etmq);

	return NULL;
}

static int cs_etm__setup_queue(struct cs_etm_auxtrace *etm,
			       struct auxtrace_queue *queue,
			       unsigned int queue_nr,
			       bool formatted,
			       int sample_cpu)
{
	struct cs_etm_queue *etmq = queue->priv;

	if (list_empty(&queue->head) || etmq)
		return 0;

	etmq = cs_etm__alloc_queue(etm, formatted, sample_cpu);

	if (!etmq)
		return -ENOMEM;

	queue->priv = etmq;
	etmq->etm = etm;
	etmq->queue_nr = queue_nr;
	etmq->offset = 0;

	return 0;
}

static int cs_etm__queue_first_cs_timestamp(struct cs_etm_auxtrace *etm,
					    struct cs_etm_queue *etmq,
					    unsigned int queue_nr)
{
	int ret = 0;
	unsigned int cs_queue_nr;
	u8 trace_chan_id;
	u64 cs_timestamp;

	/*
	 * We are under a CPU-wide trace scenario.  As such we need to know
	 * when the code that generated the traces started to execute so that
	 * it can be correlated with execution on other CPUs.  So we get a
	 * handle on the beginning of traces and decode until we find a
	 * timestamp.  The timestamp is then added to the auxtrace min heap
	 * in order to know what nibble (of all the etmqs) to decode first.
	 */
	while (1) {
		/*
		 * Fetch an aux_buffer from this etmq.  Bail if no more
		 * blocks or an error has been encountered.
		 */
		ret = cs_etm__get_data_block(etmq);
		if (ret <= 0)
			goto out;

		/*
		 * Run decoder on the trace block.  The decoder will stop when
		 * encountering a CS timestamp, a full packet queue or the end of
		 * trace for that block.
		 */
		ret = cs_etm__decode_data_block(etmq);
		if (ret)
			goto out;

		/*
		 * Function cs_etm_decoder__do_{hard|soft}_timestamp() does all
		 * the timestamp calculation for us.
		 */
		cs_timestamp = cs_etm__etmq_get_timestamp(etmq, &trace_chan_id);

		/* We found a timestamp, no need to continue. */
		if (cs_timestamp)
			break;

		/*
		 * We didn't find a timestamp so empty all the traceid packet
		 * queues before looking for another timestamp packet, either
		 * in the current data block or a new one.  Packets that were
		 * just decoded are useless since no timestamp has been
		 * associated with them.  As such simply discard them.
		 */
		cs_etm__clear_all_packet_queues(etmq);
	}

	/*
	 * We have a timestamp.  Add it to the min heap to reflect when
	 * instructions conveyed by the range packets of this traceID queue
	 * started to execute.  Once the same has been done for all the traceID
	 * queues of each etmq, redenring and decoding can start in
	 * chronological order.
	 *
	 * Note that packets decoded above are still in the traceID's packet
	 * queue and will be processed in cs_etm__process_timestamped_queues().
	 */
	cs_queue_nr = TO_CS_QUEUE_NR(queue_nr, trace_chan_id);
	ret = auxtrace_heap__add(&etm->heap, cs_queue_nr, cs_timestamp);
out:
	return ret;
}

static inline
void cs_etm__copy_last_branch_rb(struct cs_etm_queue *etmq,
				 struct cs_etm_traceid_queue *tidq)
{
	struct branch_stack *bs_src = tidq->last_branch_rb;
	struct branch_stack *bs_dst = tidq->last_branch;
	size_t nr = 0;

	/*
	 * Set the number of records before early exit: ->nr is used to
	 * determine how many branches to copy from ->entries.
	 */
	bs_dst->nr = bs_src->nr;

	/*
	 * Early exit when there is nothing to copy.
	 */
	if (!bs_src->nr)
		return;

	/*
	 * As bs_src->entries is a circular buffer, we need to copy from it in
	 * two steps.  First, copy the branches from the most recently inserted
	 * branch ->last_branch_pos until the end of bs_src->entries buffer.
	 */
	nr = etmq->etm->synth_opts.last_branch_sz - tidq->last_branch_pos;
	memcpy(&bs_dst->entries[0],
	       &bs_src->entries[tidq->last_branch_pos],
	       sizeof(struct branch_entry) * nr);

	/*
	 * If we wrapped around at least once, the branches from the beginning
	 * of the bs_src->entries buffer and until the ->last_branch_pos element
	 * are older valid branches: copy them over.  The total number of
	 * branches copied over will be equal to the number of branches asked by
	 * the user in last_branch_sz.
	 */
	if (bs_src->nr >= etmq->etm->synth_opts.last_branch_sz) {
		memcpy(&bs_dst->entries[nr],
		       &bs_src->entries[0],
		       sizeof(struct branch_entry) * tidq->last_branch_pos);
	}
}

static inline
void cs_etm__reset_last_branch_rb(struct cs_etm_traceid_queue *tidq)
{
	tidq->last_branch_pos = 0;
	tidq->last_branch_rb->nr = 0;
}

static inline int cs_etm__t32_instr_size(struct cs_etm_queue *etmq,
					 u8 trace_chan_id, u64 addr)
{
	u8 instrBytes[2];

	cs_etm__mem_access(etmq, trace_chan_id, addr, ARRAY_SIZE(instrBytes),
			   instrBytes, 0);
	/*
	 * T32 instruction size is indicated by bits[15:11] of the first
	 * 16-bit word of the instruction: 0b11101, 0b11110 and 0b11111
	 * denote a 32-bit instruction.
	 */
	return ((instrBytes[1] & 0xF8) >= 0xE8) ? 4 : 2;
}

static inline u64 cs_etm__first_executed_instr(struct cs_etm_packet *packet)
{
	/* Returns 0 for the CS_ETM_DISCONTINUITY packet */
	if (packet->sample_type == CS_ETM_DISCONTINUITY)
		return 0;

	return packet->start_addr;
}

static inline
u64 cs_etm__last_executed_instr(const struct cs_etm_packet *packet)
{
	/* Returns 0 for the CS_ETM_DISCONTINUITY packet */
	if (packet->sample_type == CS_ETM_DISCONTINUITY)
		return 0;

	return packet->end_addr - packet->last_instr_size;
}

static inline u64 cs_etm__instr_addr(struct cs_etm_queue *etmq,
				     u64 trace_chan_id,
				     const struct cs_etm_packet *packet,
				     u64 offset)
{
	if (packet->isa == CS_ETM_ISA_T32) {
		u64 addr = packet->start_addr;

		while (offset) {
			addr += cs_etm__t32_instr_size(etmq,
						       trace_chan_id, addr);
			offset--;
		}
		return addr;
	}

	/* Assume a 4 byte instruction size (A32/A64) */
	return packet->start_addr + offset * 4;
}

static void cs_etm__update_last_branch_rb(struct cs_etm_queue *etmq,
					  struct cs_etm_traceid_queue *tidq)
{
	struct branch_stack *bs = tidq->last_branch_rb;
	struct branch_entry *be;

	/*
	 * The branches are recorded in a circular buffer in reverse
	 * chronological order: we start recording from the last element of the
	 * buffer down.  After writing the first element of the stack, move the
	 * insert position back to the end of the buffer.
	 */
	if (!tidq->last_branch_pos)
		tidq->last_branch_pos = etmq->etm->synth_opts.last_branch_sz;

	tidq->last_branch_pos -= 1;

	be       = &bs->entries[tidq->last_branch_pos];
	be->from = cs_etm__last_executed_instr(tidq->prev_packet);
	be->to	 = cs_etm__first_executed_instr(tidq->packet);
	/* No support for mispredict */
	be->flags.mispred = 0;
	be->flags.predicted = 1;

	/*
	 * Increment bs->nr until reaching the number of last branches asked by
	 * the user on the command line.
	 */
	if (bs->nr < etmq->etm->synth_opts.last_branch_sz)
		bs->nr += 1;
}

static int cs_etm__inject_event(union perf_event *event,
			       struct perf_sample *sample, u64 type)
{
	event->header.size = perf_event__sample_event_size(sample, type, 0);
	return perf_event__synthesize_sample(event, type, 0, sample);
}


static int
cs_etm__get_trace(struct cs_etm_queue *etmq)
{
	struct auxtrace_buffer *aux_buffer = etmq->buffer;
	struct auxtrace_buffer *old_buffer = aux_buffer;
	struct auxtrace_queue *queue;

	queue = &etmq->etm->queues.queue_array[etmq->queue_nr];

	aux_buffer = auxtrace_buffer__next(queue, aux_buffer);

	/* If no more data, drop the previous auxtrace_buffer and return */
	if (!aux_buffer) {
		if (old_buffer)
			auxtrace_buffer__drop_data(old_buffer);
		etmq->buf_len = 0;
		return 0;
	}

	etmq->buffer = aux_buffer;

	/* If the aux_buffer doesn't have data associated, try to load it */
	if (!aux_buffer->data) {
		/* get the file desc associated with the perf data file */
		int fd = perf_data__fd(etmq->etm->session->data);

		aux_buffer->data = auxtrace_buffer__get_data(aux_buffer, fd);
		if (!aux_buffer->data)
			return -ENOMEM;
	}

	/* If valid, drop the previous buffer */
	if (old_buffer)
		auxtrace_buffer__drop_data(old_buffer);

	etmq->buf_used = 0;
	etmq->buf_len = aux_buffer->size;
	etmq->buf = aux_buffer->data;

	return etmq->buf_len;
}

static void cs_etm__set_thread(struct cs_etm_queue *etmq,
			       struct cs_etm_traceid_queue *tidq, pid_t tid,
			       ocsd_ex_level el)
{
	struct machine *machine = cs_etm__get_machine(etmq, el);

	if (tid != -1) {
		thread__zput(tidq->thread);
		tidq->thread = machine__find_thread(machine, -1, tid);
	}

	/* Couldn't find a known thread */
	if (!tidq->thread)
		tidq->thread = machine__idle_thread(machine);

	tidq->el = el;
}

int cs_etm__etmq_set_tid_el(struct cs_etm_queue *etmq, pid_t tid,
			    u8 trace_chan_id, ocsd_ex_level el)
{
	struct cs_etm_traceid_queue *tidq;

	tidq = cs_etm__etmq_get_traceid_queue(etmq, trace_chan_id);
	if (!tidq)
		return -EINVAL;

	cs_etm__set_thread(etmq, tidq, tid, el);
	return 0;
}

bool cs_etm__etmq_is_timeless(struct cs_etm_queue *etmq)
{
	return !!etmq->etm->timeless_decoding;
}

static void cs_etm__copy_insn(struct cs_etm_queue *etmq,
			      u64 trace_chan_id,
			      const struct cs_etm_packet *packet,
			      struct perf_sample *sample)
{
	/*
	 * It's pointless to read instructions for the CS_ETM_DISCONTINUITY
	 * packet, so directly bail out with 'insn_len' = 0.
	 */
	if (packet->sample_type == CS_ETM_DISCONTINUITY) {
		sample->insn_len = 0;
		return;
	}

	/*
	 * T32 instruction size might be 32-bit or 16-bit, decide by calling
	 * cs_etm__t32_instr_size().
	 */
	if (packet->isa == CS_ETM_ISA_T32)
		sample->insn_len = cs_etm__t32_instr_size(etmq, trace_chan_id,
							  sample->ip);
	/* Otherwise, A64 and A32 instruction size are always 32-bit. */
	else
		sample->insn_len = 4;

	cs_etm__mem_access(etmq, trace_chan_id, sample->ip, sample->insn_len,
			   (void *)sample->insn, 0);
}

u64 cs_etm__convert_sample_time(struct cs_etm_queue *etmq, u64 cs_timestamp)
{
	struct cs_etm_auxtrace *etm = etmq->etm;

	if (etm->has_virtual_ts)
		return tsc_to_perf_time(cs_timestamp, &etm->tc);
	else
		return cs_timestamp;
}

static inline u64 cs_etm__resolve_sample_time(struct cs_etm_queue *etmq,
					       struct cs_etm_traceid_queue *tidq)
{
	struct cs_etm_auxtrace *etm = etmq->etm;
	struct cs_etm_packet_queue *packet_queue = &tidq->packet_queue;

	if (!etm->timeless_decoding && etm->has_virtual_ts)
		return packet_queue->cs_timestamp;
	else
		return etm->latest_kernel_timestamp;
}

static int cs_etm__synth_instruction_sample(struct cs_etm_queue *etmq,
					    struct cs_etm_traceid_queue *tidq,
					    u64 addr, u64 period)
{
	int ret = 0;
	struct cs_etm_auxtrace *etm = etmq->etm;
	union perf_event *event = tidq->event_buf;
	struct perf_sample sample = {.ip = 0,};

	event->sample.header.type = PERF_RECORD_SAMPLE;
	event->sample.header.misc = cs_etm__cpu_mode(etmq, addr, tidq->el);
	event->sample.header.size = sizeof(struct perf_event_header);

	/* Set time field based on etm auxtrace config. */
	sample.time = cs_etm__resolve_sample_time(etmq, tidq);

	sample.ip = addr;
	sample.pid = thread__pid(tidq->thread);
	sample.tid = thread__tid(tidq->thread);
	sample.id = etmq->etm->instructions_id;
	sample.stream_id = etmq->etm->instructions_id;
	sample.period = period;
	sample.cpu = tidq->packet->cpu;
	sample.flags = tidq->prev_packet->flags;
	sample.cpumode = event->sample.header.misc;

	cs_etm__copy_insn(etmq, tidq->trace_chan_id, tidq->packet, &sample);

	if (etm->synth_opts.last_branch)
		sample.branch_stack = tidq->last_branch;

	if (etm->synth_opts.inject) {
		ret = cs_etm__inject_event(event, &sample,
					   etm->instructions_sample_type);
		if (ret)
			return ret;
	}

	ret = perf_session__deliver_synth_event(etm->session, event, &sample);

	if (ret)
		pr_err(
			"CS ETM Trace: failed to deliver instruction event, error %d\n",
			ret);

	return ret;
}

/*
 * The cs etm packet encodes an instruction range between a branch target
 * and the next taken branch. Generate sample accordingly.
 */
static int cs_etm__synth_branch_sample(struct cs_etm_queue *etmq,
				       struct cs_etm_traceid_queue *tidq)
{
	int ret = 0;
	struct cs_etm_auxtrace *etm = etmq->etm;
	struct perf_sample sample = {.ip = 0,};
	union perf_event *event = tidq->event_buf;
	struct dummy_branch_stack {
		u64			nr;
		u64			hw_idx;
		struct branch_entry	entries;
	} dummy_bs;
	u64 ip;

	ip = cs_etm__last_executed_instr(tidq->prev_packet);

	event->sample.header.type = PERF_RECORD_SAMPLE;
	event->sample.header.misc = cs_etm__cpu_mode(etmq, ip,
						     tidq->prev_packet_el);
	event->sample.header.size = sizeof(struct perf_event_header);

	/* Set time field based on etm auxtrace config. */
	sample.time = cs_etm__resolve_sample_time(etmq, tidq);

	sample.ip = ip;
	sample.pid = thread__pid(tidq->prev_packet_thread);
	sample.tid = thread__tid(tidq->prev_packet_thread);
	sample.addr = cs_etm__first_executed_instr(tidq->packet);
	sample.id = etmq->etm->branches_id;
	sample.stream_id = etmq->etm->branches_id;
	sample.period = 1;
	sample.cpu = tidq->packet->cpu;
	sample.flags = tidq->prev_packet->flags;
	sample.cpumode = event->sample.header.misc;

	cs_etm__copy_insn(etmq, tidq->trace_chan_id, tidq->prev_packet,
			  &sample);

	/*
	 * perf report cannot handle events without a branch stack
	 */
	if (etm->synth_opts.last_branch) {
		dummy_bs = (struct dummy_branch_stack){
			.nr = 1,
			.hw_idx = -1ULL,
			.entries = {
				.from = sample.ip,
				.to = sample.addr,
			},
		};
		sample.branch_stack = (struct branch_stack *)&dummy_bs;
	}

	if (etm->synth_opts.inject) {
		ret = cs_etm__inject_event(event, &sample,
					   etm->branches_sample_type);
		if (ret)
			return ret;
	}

	ret = perf_session__deliver_synth_event(etm->session, event, &sample);

	if (ret)
		pr_err(
		"CS ETM Trace: failed to deliver instruction event, error %d\n",
		ret);

	return ret;
}

struct cs_etm_synth {
	struct perf_tool dummy_tool;
	struct perf_session *session;
};

static int cs_etm__event_synth(struct perf_tool *tool,
			       union perf_event *event,
			       struct perf_sample *sample __maybe_unused,
			       struct machine *machine __maybe_unused)
{
	struct cs_etm_synth *cs_etm_synth =
		      container_of(tool, struct cs_etm_synth, dummy_tool);

	return perf_session__deliver_synth_event(cs_etm_synth->session,
						 event, NULL);
}

static int cs_etm__synth_event(struct perf_session *session,
			       struct perf_event_attr *attr, u64 id)
{
	struct cs_etm_synth cs_etm_synth;

	memset(&cs_etm_synth, 0, sizeof(struct cs_etm_synth));
	cs_etm_synth.session = session;

	return perf_event__synthesize_attr(&cs_etm_synth.dummy_tool, attr, 1,
					   &id, cs_etm__event_synth);
}

static int cs_etm__synth_events(struct cs_etm_auxtrace *etm,
				struct perf_session *session)
{
	struct evlist *evlist = session->evlist;
	struct evsel *evsel;
	struct perf_event_attr attr;
	bool found = false;
	u64 id;
	int err;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->core.attr.type == etm->pmu_type) {
			found = true;
			break;
		}
	}

	if (!found) {
		pr_debug("No selected events with CoreSight Trace data\n");
		return 0;
	}

	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.sample_type = evsel->core.attr.sample_type & PERF_SAMPLE_MASK;
	attr.sample_type |= PERF_SAMPLE_IP | PERF_SAMPLE_TID |
			    PERF_SAMPLE_PERIOD;
	if (etm->timeless_decoding)
		attr.sample_type &= ~(u64)PERF_SAMPLE_TIME;
	else
		attr.sample_type |= PERF_SAMPLE_TIME;

	attr.exclude_user = evsel->core.attr.exclude_user;
	attr.exclude_kernel = evsel->core.attr.exclude_kernel;
	attr.exclude_hv = evsel->core.attr.exclude_hv;
	attr.exclude_host = evsel->core.attr.exclude_host;
	attr.exclude_guest = evsel->core.attr.exclude_guest;
	attr.sample_id_all = evsel->core.attr.sample_id_all;
	attr.read_format = evsel->core.attr.read_format;

	/* create new id val to be a fixed offset from evsel id */
	id = evsel->core.id[0] + 1000000000;

	if (!id)
		id = 1;

	if (etm->synth_opts.branches) {
		attr.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
		attr.sample_period = 1;
		attr.sample_type |= PERF_SAMPLE_ADDR;
		err = cs_etm__synth_event(session, &attr, id);
		if (err)
			return err;
		etm->branches_sample_type = attr.sample_type;
		etm->branches_id = id;
		id += 1;
		attr.sample_type &= ~(u64)PERF_SAMPLE_ADDR;
	}

	if (etm->synth_opts.last_branch) {
		attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
		/*
		 * We don't use the hardware index, but the sample generation
		 * code uses the new format branch_stack with this field,
		 * so the event attributes must indicate that it's present.
		 */
		attr.branch_sample_type |= PERF_SAMPLE_BRANCH_HW_INDEX;
	}

	if (etm->synth_opts.instructions) {
		attr.config = PERF_COUNT_HW_INSTRUCTIONS;
		attr.sample_period = etm->synth_opts.period;
		etm->instructions_sample_period = attr.sample_period;
		err = cs_etm__synth_event(session, &attr, id);
		if (err)
			return err;
		etm->instructions_sample_type = attr.sample_type;
		etm->instructions_id = id;
		id += 1;
	}

	return 0;
}

static int cs_etm__sample(struct cs_etm_queue *etmq,
			  struct cs_etm_traceid_queue *tidq)
{
	struct cs_etm_auxtrace *etm = etmq->etm;
	int ret;
	u8 trace_chan_id = tidq->trace_chan_id;
	u64 instrs_prev;

	/* Get instructions remainder from previous packet */
	instrs_prev = tidq->period_instructions;

	tidq->period_instructions += tidq->packet->instr_count;

	/*
	 * Record a branch when the last instruction in
	 * PREV_PACKET is a branch.
	 */
	if (etm->synth_opts.last_branch &&
	    tidq->prev_packet->sample_type == CS_ETM_RANGE &&
	    tidq->prev_packet->last_instr_taken_branch)
		cs_etm__update_last_branch_rb(etmq, tidq);

	if (etm->synth_opts.instructions &&
	    tidq->period_instructions >= etm->instructions_sample_period) {
		/*
		 * Emit instruction sample periodically
		 * TODO: allow period to be defined in cycles and clock time
		 */

		/*
		 * Below diagram demonstrates the instruction samples
		 * generation flows:
		 *
		 *    Instrs     Instrs       Instrs       Instrs
		 *   Sample(n)  Sample(n+1)  Sample(n+2)  Sample(n+3)
		 *    |            |            |            |
		 *    V            V            V            V
		 *   --------------------------------------------------
		 *            ^                                  ^
		 *            |                                  |
		 *         Period                             Period
		 *    instructions(Pi)                   instructions(Pi')
		 *
		 *            |                                  |
		 *            \---------------- -----------------/
		 *                             V
		 *                 tidq->packet->instr_count
		 *
		 * Instrs Sample(n...) are the synthesised samples occurring
		 * every etm->instructions_sample_period instructions - as
		 * defined on the perf command line.  Sample(n) is being the
		 * last sample before the current etm packet, n+1 to n+3
		 * samples are generated from the current etm packet.
		 *
		 * tidq->packet->instr_count represents the number of
		 * instructions in the current etm packet.
		 *
		 * Period instructions (Pi) contains the number of
		 * instructions executed after the sample point(n) from the
		 * previous etm packet.  This will always be less than
		 * etm->instructions_sample_period.
		 *
		 * When generate new samples, it combines with two parts
		 * instructions, one is the tail of the old packet and another
		 * is the head of the new coming packet, to generate
		 * sample(n+1); sample(n+2) and sample(n+3) consume the
		 * instructions with sample period.  After sample(n+3), the rest
		 * instructions will be used by later packet and it is assigned
		 * to tidq->period_instructions for next round calculation.
		 */

		/*
		 * Get the initial offset into the current packet instructions;
		 * entry conditions ensure that instrs_prev is less than
		 * etm->instructions_sample_period.
		 */
		u64 offset = etm->instructions_sample_period - instrs_prev;
		u64 addr;

		/* Prepare last branches for instruction sample */
		if (etm->synth_opts.last_branch)
			cs_etm__copy_last_branch_rb(etmq, tidq);

		while (tidq->period_instructions >=
				etm->instructions_sample_period) {
			/*
			 * Calculate the address of the sampled instruction (-1
			 * as sample is reported as though instruction has just
			 * been executed, but PC has not advanced to next
			 * instruction)
			 */
			addr = cs_etm__instr_addr(etmq, trace_chan_id,
						  tidq->packet, offset - 1);
			ret = cs_etm__synth_instruction_sample(
				etmq, tidq, addr,
				etm->instructions_sample_period);
			if (ret)
				return ret;

			offset += etm->instructions_sample_period;
			tidq->period_instructions -=
				etm->instructions_sample_period;
		}
	}

	if (etm->synth_opts.branches) {
		bool generate_sample = false;

		/* Generate sample for tracing on packet */
		if (tidq->prev_packet->sample_type == CS_ETM_DISCONTINUITY)
			generate_sample = true;

		/* Generate sample for branch taken packet */
		if (tidq->prev_packet->sample_type == CS_ETM_RANGE &&
		    tidq->prev_packet->last_instr_taken_branch)
			generate_sample = true;

		if (generate_sample) {
			ret = cs_etm__synth_branch_sample(etmq, tidq);
			if (ret)
				return ret;
		}
	}

	cs_etm__packet_swap(etm, tidq);

	return 0;
}

static int cs_etm__exception(struct cs_etm_traceid_queue *tidq)
{
	/*
	 * When the exception packet is inserted, whether the last instruction
	 * in previous range packet is taken branch or not, we need to force
	 * to set 'prev_packet->last_instr_taken_branch' to true.  This ensures
	 * to generate branch sample for the instruction range before the
	 * exception is trapped to kernel or before the exception returning.
	 *
	 * The exception packet includes the dummy address values, so don't
	 * swap PACKET with PREV_PACKET.  This keeps PREV_PACKET to be useful
	 * for generating instruction and branch samples.
	 */
	if (tidq->prev_packet->sample_type == CS_ETM_RANGE)
		tidq->prev_packet->last_instr_taken_branch = true;

	return 0;
}

static int cs_etm__flush(struct cs_etm_queue *etmq,
			 struct cs_etm_traceid_queue *tidq)
{
	int err = 0;
	struct cs_etm_auxtrace *etm = etmq->etm;

	/* Handle start tracing packet */
	if (tidq->prev_packet->sample_type == CS_ETM_EMPTY)
		goto swap_packet;

	if (etmq->etm->synth_opts.last_branch &&
	    etmq->etm->synth_opts.instructions &&
	    tidq->prev_packet->sample_type == CS_ETM_RANGE) {
		u64 addr;

		/* Prepare last branches for instruction sample */
		cs_etm__copy_last_branch_rb(etmq, tidq);

		/*
		 * Generate a last branch event for the branches left in the
		 * circular buffer at the end of the trace.
		 *
		 * Use the address of the end of the last reported execution
		 * range
		 */
		addr = cs_etm__last_executed_instr(tidq->prev_packet);

		err = cs_etm__synth_instruction_sample(
			etmq, tidq, addr,
			tidq->period_instructions);
		if (err)
			return err;

		tidq->period_instructions = 0;

	}

	if (etm->synth_opts.branches &&
	    tidq->prev_packet->sample_type == CS_ETM_RANGE) {
		err = cs_etm__synth_branch_sample(etmq, tidq);
		if (err)
			return err;
	}

swap_packet:
	cs_etm__packet_swap(etm, tidq);

	/* Reset last branches after flush the trace */
	if (etm->synth_opts.last_branch)
		cs_etm__reset_last_branch_rb(tidq);

	return err;
}

static int cs_etm__end_block(struct cs_etm_queue *etmq,
			     struct cs_etm_traceid_queue *tidq)
{
	int err;

	/*
	 * It has no new packet coming and 'etmq->packet' contains the stale
	 * packet which was set at the previous time with packets swapping;
	 * so skip to generate branch sample to avoid stale packet.
	 *
	 * For this case only flush branch stack and generate a last branch
	 * event for the branches left in the circular buffer at the end of
	 * the trace.
	 */
	if (etmq->etm->synth_opts.last_branch &&
	    etmq->etm->synth_opts.instructions &&
	    tidq->prev_packet->sample_type == CS_ETM_RANGE) {
		u64 addr;

		/* Prepare last branches for instruction sample */
		cs_etm__copy_last_branch_rb(etmq, tidq);

		/*
		 * Use the address of the end of the last reported execution
		 * range.
		 */
		addr = cs_etm__last_executed_instr(tidq->prev_packet);

		err = cs_etm__synth_instruction_sample(
			etmq, tidq, addr,
			tidq->period_instructions);
		if (err)
			return err;

		tidq->period_instructions = 0;
	}

	return 0;
}
/*
 * cs_etm__get_data_block: Fetch a block from the auxtrace_buffer queue
 *			   if need be.
 * Returns:	< 0	if error
 *		= 0	if no more auxtrace_buffer to read
 *		> 0	if the current buffer isn't empty yet
 */
static int cs_etm__get_data_block(struct cs_etm_queue *etmq)
{
	int ret;

	if (!etmq->buf_len) {
		ret = cs_etm__get_trace(etmq);
		if (ret <= 0)
			return ret;
		/*
		 * We cannot assume consecutive blocks in the data file
		 * are contiguous, reset the decoder to force re-sync.
		 */
		ret = cs_etm_decoder__reset(etmq->decoder);
		if (ret)
			return ret;
	}

	return etmq->buf_len;
}

static bool cs_etm__is_svc_instr(struct cs_etm_queue *etmq, u8 trace_chan_id,
				 struct cs_etm_packet *packet,
				 u64 end_addr)
{
	/* Initialise to keep compiler happy */
	u16 instr16 = 0;
	u32 instr32 = 0;
	u64 addr;

	switch (packet->isa) {
	case CS_ETM_ISA_T32:
		/*
		 * The SVC of T32 is defined in ARM DDI 0487D.a, F5.1.247:
		 *
		 *  b'15         b'8
		 * +-----------------+--------+
		 * | 1 1 0 1 1 1 1 1 |  imm8  |
		 * +-----------------+--------+
		 *
		 * According to the specification, it only defines SVC for T32
		 * with 16 bits instruction and has no definition for 32bits;
		 * so below only read 2 bytes as instruction size for T32.
		 */
		addr = end_addr - 2;
		cs_etm__mem_access(etmq, trace_chan_id, addr, sizeof(instr16),
				   (u8 *)&instr16, 0);
		if ((instr16 & 0xFF00) == 0xDF00)
			return true;

		break;
	case CS_ETM_ISA_A32:
		/*
		 * The SVC of A32 is defined in ARM DDI 0487D.a, F5.1.247:
		 *
		 *  b'31 b'28 b'27 b'24
		 * +---------+---------+-------------------------+
		 * |  !1111  | 1 1 1 1 |        imm24            |
		 * +---------+---------+-------------------------+
		 */
		addr = end_addr - 4;
		cs_etm__mem_access(etmq, trace_chan_id, addr, sizeof(instr32),
				   (u8 *)&instr32, 0);
		if ((instr32 & 0x0F000000) == 0x0F000000 &&
		    (instr32 & 0xF0000000) != 0xF0000000)
			return true;

		break;
	case CS_ETM_ISA_A64:
		/*
		 * The SVC of A64 is defined in ARM DDI 0487D.a, C6.2.294:
		 *
		 *  b'31               b'21           b'4     b'0
		 * +-----------------------+---------+-----------+
		 * | 1 1 0 1 0 1 0 0 0 0 0 |  imm16  | 0 0 0 0 1 |
		 * +-----------------------+---------+-----------+
		 */
		addr = end_addr - 4;
		cs_etm__mem_access(etmq, trace_chan_id, addr, sizeof(instr32),
				   (u8 *)&instr32, 0);
		if ((instr32 & 0xFFE0001F) == 0xd4000001)
			return true;

		break;
	case CS_ETM_ISA_UNKNOWN:
	default:
		break;
	}

	return false;
}

static bool cs_etm__is_syscall(struct cs_etm_queue *etmq,
			       struct cs_etm_traceid_queue *tidq, u64 magic)
{
	u8 trace_chan_id = tidq->trace_chan_id;
	struct cs_etm_packet *packet = tidq->packet;
	struct cs_etm_packet *prev_packet = tidq->prev_packet;

	if (magic == __perf_cs_etmv3_magic)
		if (packet->exception_number == CS_ETMV3_EXC_SVC)
			return true;

	/*
	 * ETMv4 exception type CS_ETMV4_EXC_CALL covers SVC, SMC and
	 * HVC cases; need to check if it's SVC instruction based on
	 * packet address.
	 */
	if (magic == __perf_cs_etmv4_magic) {
		if (packet->exception_number == CS_ETMV4_EXC_CALL &&
		    cs_etm__is_svc_instr(etmq, trace_chan_id, prev_packet,
					 prev_packet->end_addr))
			return true;
	}

	return false;
}

static bool cs_etm__is_async_exception(struct cs_etm_traceid_queue *tidq,
				       u64 magic)
{
	struct cs_etm_packet *packet = tidq->packet;

	if (magic == __perf_cs_etmv3_magic)
		if (packet->exception_number == CS_ETMV3_EXC_DEBUG_HALT ||
		    packet->exception_number == CS_ETMV3_EXC_ASYNC_DATA_ABORT ||
		    packet->exception_number == CS_ETMV3_EXC_PE_RESET ||
		    packet->exception_number == CS_ETMV3_EXC_IRQ ||
		    packet->exception_number == CS_ETMV3_EXC_FIQ)
			return true;

	if (magic == __perf_cs_etmv4_magic)
		if (packet->exception_number == CS_ETMV4_EXC_RESET ||
		    packet->exception_number == CS_ETMV4_EXC_DEBUG_HALT ||
		    packet->exception_number == CS_ETMV4_EXC_SYSTEM_ERROR ||
		    packet->exception_number == CS_ETMV4_EXC_INST_DEBUG ||
		    packet->exception_number == CS_ETMV4_EXC_DATA_DEBUG ||
		    packet->exception_number == CS_ETMV4_EXC_IRQ ||
		    packet->exception_number == CS_ETMV4_EXC_FIQ)
			return true;

	return false;
}

static bool cs_etm__is_sync_exception(struct cs_etm_queue *etmq,
				      struct cs_etm_traceid_queue *tidq,
				      u64 magic)
{
	u8 trace_chan_id = tidq->trace_chan_id;
	struct cs_etm_packet *packet = tidq->packet;
	struct cs_etm_packet *prev_packet = tidq->prev_packet;

	if (magic == __perf_cs_etmv3_magic)
		if (packet->exception_number == CS_ETMV3_EXC_SMC ||
		    packet->exception_number == CS_ETMV3_EXC_HYP ||
		    packet->exception_number == CS_ETMV3_EXC_JAZELLE_THUMBEE ||
		    packet->exception_number == CS_ETMV3_EXC_UNDEFINED_INSTR ||
		    packet->exception_number == CS_ETMV3_EXC_PREFETCH_ABORT ||
		    packet->exception_number == CS_ETMV3_EXC_DATA_FAULT ||
		    packet->exception_number == CS_ETMV3_EXC_GENERIC)
			return true;

	if (magic == __perf_cs_etmv4_magic) {
		if (packet->exception_number == CS_ETMV4_EXC_TRAP ||
		    packet->exception_number == CS_ETMV4_EXC_ALIGNMENT ||
		    packet->exception_number == CS_ETMV4_EXC_INST_FAULT ||
		    packet->exception_number == CS_ETMV4_EXC_DATA_FAULT)
			return true;

		/*
		 * For CS_ETMV4_EXC_CALL, except SVC other instructions
		 * (SMC, HVC) are taken as sync exceptions.
		 */
		if (packet->exception_number == CS_ETMV4_EXC_CALL &&
		    !cs_etm__is_svc_instr(etmq, trace_chan_id, prev_packet,
					  prev_packet->end_addr))
			return true;

		/*
		 * ETMv4 has 5 bits for exception number; if the numbers
		 * are in the range ( CS_ETMV4_EXC_FIQ, CS_ETMV4_EXC_END ]
		 * they are implementation defined exceptions.
		 *
		 * For this case, simply take it as sync exception.
		 */
		if (packet->exception_number > CS_ETMV4_EXC_FIQ &&
		    packet->exception_number <= CS_ETMV4_EXC_END)
			return true;
	}

	return false;
}

static int cs_etm__set_sample_flags(struct cs_etm_queue *etmq,
				    struct cs_etm_traceid_queue *tidq)
{
	struct cs_etm_packet *packet = tidq->packet;
	struct cs_etm_packet *prev_packet = tidq->prev_packet;
	u8 trace_chan_id = tidq->trace_chan_id;
	u64 magic;
	int ret;

	switch (packet->sample_type) {
	case CS_ETM_RANGE:
		/*
		 * Immediate branch instruction without neither link nor
		 * return flag, it's normal branch instruction within
		 * the function.
		 */
		if (packet->last_instr_type == OCSD_INSTR_BR &&
		    packet->last_instr_subtype == OCSD_S_INSTR_NONE) {
			packet->flags = PERF_IP_FLAG_BRANCH;

			if (packet->last_instr_cond)
				packet->flags |= PERF_IP_FLAG_CONDITIONAL;
		}

		/*
		 * Immediate branch instruction with link (e.g. BL), this is
		 * branch instruction for function call.
		 */
		if (packet->last_instr_type == OCSD_INSTR_BR &&
		    packet->last_instr_subtype == OCSD_S_INSTR_BR_LINK)
			packet->flags = PERF_IP_FLAG_BRANCH |
					PERF_IP_FLAG_CALL;

		/*
		 * Indirect branch instruction with link (e.g. BLR), this is
		 * branch instruction for function call.
		 */
		if (packet->last_instr_type == OCSD_INSTR_BR_INDIRECT &&
		    packet->last_instr_subtype == OCSD_S_INSTR_BR_LINK)
			packet->flags = PERF_IP_FLAG_BRANCH |
					PERF_IP_FLAG_CALL;

		/*
		 * Indirect branch instruction with subtype of
		 * OCSD_S_INSTR_V7_IMPLIED_RET, this is explicit hint for
		 * function return for A32/T32.
		 */
		if (packet->last_instr_type == OCSD_INSTR_BR_INDIRECT &&
		    packet->last_instr_subtype == OCSD_S_INSTR_V7_IMPLIED_RET)
			packet->flags = PERF_IP_FLAG_BRANCH |
					PERF_IP_FLAG_RETURN;

		/*
		 * Indirect branch instruction without link (e.g. BR), usually
		 * this is used for function return, especially for functions
		 * within dynamic link lib.
		 */
		if (packet->last_instr_type == OCSD_INSTR_BR_INDIRECT &&
		    packet->last_instr_subtype == OCSD_S_INSTR_NONE)
			packet->flags = PERF_IP_FLAG_BRANCH |
					PERF_IP_FLAG_RETURN;

		/* Return instruction for function return. */
		if (packet->last_instr_type == OCSD_INSTR_BR_INDIRECT &&
		    packet->last_instr_subtype == OCSD_S_INSTR_V8_RET)
			packet->flags = PERF_IP_FLAG_BRANCH |
					PERF_IP_FLAG_RETURN;

		/*
		 * Decoder might insert a discontinuity in the middle of
		 * instruction packets, fixup prev_packet with flag
		 * PERF_IP_FLAG_TRACE_BEGIN to indicate restarting trace.
		 */
		if (prev_packet->sample_type == CS_ETM_DISCONTINUITY)
			prev_packet->flags |= PERF_IP_FLAG_BRANCH |
					      PERF_IP_FLAG_TRACE_BEGIN;

		/*
		 * If the previous packet is an exception return packet
		 * and the return address just follows SVC instruction,
		 * it needs to calibrate the previous packet sample flags
		 * as PERF_IP_FLAG_SYSCALLRET.
		 */
		if (prev_packet->flags == (PERF_IP_FLAG_BRANCH |
					   PERF_IP_FLAG_RETURN |
					   PERF_IP_FLAG_INTERRUPT) &&
		    cs_etm__is_svc_instr(etmq, trace_chan_id,
					 packet, packet->start_addr))
			prev_packet->flags = PERF_IP_FLAG_BRANCH |
					     PERF_IP_FLAG_RETURN |
					     PERF_IP_FLAG_SYSCALLRET;
		break;
	case CS_ETM_DISCONTINUITY:
		/*
		 * The trace is discontinuous, if the previous packet is
		 * instruction packet, set flag PERF_IP_FLAG_TRACE_END
		 * for previous packet.
		 */
		if (prev_packet->sample_type == CS_ETM_RANGE)
			prev_packet->flags |= PERF_IP_FLAG_BRANCH |
					      PERF_IP_FLAG_TRACE_END;
		break;
	case CS_ETM_EXCEPTION:
		ret = cs_etm__get_magic(packet->trace_chan_id, &magic);
		if (ret)
			return ret;

		/* The exception is for system call. */
		if (cs_etm__is_syscall(etmq, tidq, magic))
			packet->flags = PERF_IP_FLAG_BRANCH |
					PERF_IP_FLAG_CALL |
					PERF_IP_FLAG_SYSCALLRET;
		/*
		 * The exceptions are triggered by external signals from bus,
		 * interrupt controller, debug module, PE reset or halt.
		 */
		else if (cs_etm__is_async_exception(tidq, magic))
			packet->flags = PERF_IP_FLAG_BRANCH |
					PERF_IP_FLAG_CALL |
					PERF_IP_FLAG_ASYNC |
					PERF_IP_FLAG_INTERRUPT;
		/*
		 * Otherwise, exception is caused by trap, instruction &
		 * data fault, or alignment errors.
		 */
		else if (cs_etm__is_sync_exception(etmq, tidq, magic))
			packet->flags = PERF_IP_FLAG_BRANCH |
					PERF_IP_FLAG_CALL |
					PERF_IP_FLAG_INTERRUPT;

		/*
		 * When the exception packet is inserted, since exception
		 * packet is not used standalone for generating samples
		 * and it's affiliation to the previous instruction range
		 * packet; so set previous range packet flags to tell perf
		 * it is an exception taken branch.
		 */
		if (prev_packet->sample_type == CS_ETM_RANGE)
			prev_packet->flags = packet->flags;
		break;
	case CS_ETM_EXCEPTION_RET:
		/*
		 * When the exception return packet is inserted, since
		 * exception return packet is not used standalone for
		 * generating samples and it's affiliation to the previous
		 * instruction range packet; so set previous range packet
		 * flags to tell perf it is an exception return branch.
		 *
		 * The exception return can be for either system call or
		 * other exception types; unfortunately the packet doesn't
		 * contain exception type related info so we cannot decide
		 * the exception type purely based on exception return packet.
		 * If we record the exception number from exception packet and
		 * reuse it for exception return packet, this is not reliable
		 * due the trace can be discontinuity or the interrupt can
		 * be nested, thus the recorded exception number cannot be
		 * used for exception return packet for these two cases.
		 *
		 * For exception return packet, we only need to distinguish the
		 * packet is for system call or for other types.  Thus the
		 * decision can be deferred when receive the next packet which
		 * contains the return address, based on the return address we
		 * can read out the previous instruction and check if it's a
		 * system call instruction and then calibrate the sample flag
		 * as needed.
		 */
		if (prev_packet->sample_type == CS_ETM_RANGE)
			prev_packet->flags = PERF_IP_FLAG_BRANCH |
					     PERF_IP_FLAG_RETURN |
					     PERF_IP_FLAG_INTERRUPT;
		break;
	case CS_ETM_EMPTY:
	default:
		break;
	}

	return 0;
}

static int cs_etm__decode_data_block(struct cs_etm_queue *etmq)
{
	int ret = 0;
	size_t processed = 0;

	/*
	 * Packets are decoded and added to the decoder's packet queue
	 * until the decoder packet processing callback has requested that
	 * processing stops or there is nothing left in the buffer.  Normal
	 * operations that stop processing are a timestamp packet or a full
	 * decoder buffer queue.
	 */
	ret = cs_etm_decoder__process_data_block(etmq->decoder,
						 etmq->offset,
						 &etmq->buf[etmq->buf_used],
						 etmq->buf_len,
						 &processed);
	if (ret)
		goto out;

	etmq->offset += processed;
	etmq->buf_used += processed;
	etmq->buf_len -= processed;

out:
	return ret;
}

static int cs_etm__process_traceid_queue(struct cs_etm_queue *etmq,
					 struct cs_etm_traceid_queue *tidq)
{
	int ret;
	struct cs_etm_packet_queue *packet_queue;

	packet_queue = &tidq->packet_queue;

	/* Process each packet in this chunk */
	while (1) {
		ret = cs_etm_decoder__get_packet(packet_queue,
						 tidq->packet);
		if (ret <= 0)
			/*
			 * Stop processing this chunk on
			 * end of data or error
			 */
			break;

		/*
		 * Since packet addresses are swapped in packet
		 * handling within below switch() statements,
		 * thus setting sample flags must be called
		 * prior to switch() statement to use address
		 * information before packets swapping.
		 */
		ret = cs_etm__set_sample_flags(etmq, tidq);
		if (ret < 0)
			break;

		switch (tidq->packet->sample_type) {
		case CS_ETM_RANGE:
			/*
			 * If the packet contains an instruction
			 * range, generate instruction sequence
			 * events.
			 */
			cs_etm__sample(etmq, tidq);
			break;
		case CS_ETM_EXCEPTION:
		case CS_ETM_EXCEPTION_RET:
			/*
			 * If the exception packet is coming,
			 * make sure the previous instruction
			 * range packet to be handled properly.
			 */
			cs_etm__exception(tidq);
			break;
		case CS_ETM_DISCONTINUITY:
			/*
			 * Discontinuity in trace, flush
			 * previous branch stack
			 */
			cs_etm__flush(etmq, tidq);
			break;
		case CS_ETM_EMPTY:
			/*
			 * Should not receive empty packet,
			 * report error.
			 */
			pr_err("CS ETM Trace: empty packet\n");
			return -EINVAL;
		default:
			break;
		}
	}

	return ret;
}

static void cs_etm__clear_all_traceid_queues(struct cs_etm_queue *etmq)
{
	int idx;
	struct int_node *inode;
	struct cs_etm_traceid_queue *tidq;
	struct intlist *traceid_queues_list = etmq->traceid_queues_list;

	intlist__for_each_entry(inode, traceid_queues_list) {
		idx = (int)(intptr_t)inode->priv;
		tidq = etmq->traceid_queues[idx];

		/* Ignore return value */
		cs_etm__process_traceid_queue(etmq, tidq);
	}
}

static int cs_etm__run_per_thread_timeless_decoder(struct cs_etm_queue *etmq)
{
	int err = 0;
	struct cs_etm_traceid_queue *tidq;

	tidq = cs_etm__etmq_get_traceid_queue(etmq, CS_ETM_PER_THREAD_TRACEID);
	if (!tidq)
		return -EINVAL;

	/* Go through each buffer in the queue and decode them one by one */
	while (1) {
		err = cs_etm__get_data_block(etmq);
		if (err <= 0)
			return err;

		/* Run trace decoder until buffer consumed or end of trace */
		do {
			err = cs_etm__decode_data_block(etmq);
			if (err)
				return err;

			/*
			 * Process each packet in this chunk, nothing to do if
			 * an error occurs other than hoping the next one will
			 * be better.
			 */
			err = cs_etm__process_traceid_queue(etmq, tidq);

		} while (etmq->buf_len);

		if (err == 0)
			/* Flush any remaining branch stack entries */
			err = cs_etm__end_block(etmq, tidq);
	}

	return err;
}

static int cs_etm__run_per_cpu_timeless_decoder(struct cs_etm_queue *etmq)
{
	int idx, err = 0;
	struct cs_etm_traceid_queue *tidq;
	struct int_node *inode;

	/* Go through each buffer in the queue and decode them one by one */
	while (1) {
		err = cs_etm__get_data_block(etmq);
		if (err <= 0)
			return err;

		/* Run trace decoder until buffer consumed or end of trace */
		do {
			err = cs_etm__decode_data_block(etmq);
			if (err)
				return err;

			/*
			 * cs_etm__run_per_thread_timeless_decoder() runs on a
			 * single traceID queue because each TID has a separate
			 * buffer. But here in per-cpu mode we need to iterate
			 * over each channel instead.
			 */
			intlist__for_each_entry(inode,
						etmq->traceid_queues_list) {
				idx = (int)(intptr_t)inode->priv;
				tidq = etmq->traceid_queues[idx];
				cs_etm__process_traceid_queue(etmq, tidq);
			}
		} while (etmq->buf_len);

		intlist__for_each_entry(inode, etmq->traceid_queues_list) {
			idx = (int)(intptr_t)inode->priv;
			tidq = etmq->traceid_queues[idx];
			/* Flush any remaining branch stack entries */
			err = cs_etm__end_block(etmq, tidq);
			if (err)
				return err;
		}
	}

	return err;
}

static int cs_etm__process_timeless_queues(struct cs_etm_auxtrace *etm,
					   pid_t tid)
{
	unsigned int i;
	struct auxtrace_queues *queues = &etm->queues;

	for (i = 0; i < queues->nr_queues; i++) {
		struct auxtrace_queue *queue = &etm->queues.queue_array[i];
		struct cs_etm_queue *etmq = queue->priv;
		struct cs_etm_traceid_queue *tidq;

		if (!etmq)
			continue;

		if (etm->per_thread_decoding) {
			tidq = cs_etm__etmq_get_traceid_queue(
				etmq, CS_ETM_PER_THREAD_TRACEID);

			if (!tidq)
				continue;

			if (tid == -1 || thread__tid(tidq->thread) == tid)
				cs_etm__run_per_thread_timeless_decoder(etmq);
		} else
			cs_etm__run_per_cpu_timeless_decoder(etmq);
	}

	return 0;
}

static int cs_etm__process_timestamped_queues(struct cs_etm_auxtrace *etm)
{
	int ret = 0;
	unsigned int cs_queue_nr, queue_nr, i;
	u8 trace_chan_id;
	u64 cs_timestamp;
	struct auxtrace_queue *queue;
	struct cs_etm_queue *etmq;
	struct cs_etm_traceid_queue *tidq;

	/*
	 * Pre-populate the heap with one entry from each queue so that we can
	 * start processing in time order across all queues.
	 */
	for (i = 0; i < etm->queues.nr_queues; i++) {
		etmq = etm->queues.queue_array[i].priv;
		if (!etmq)
			continue;

		ret = cs_etm__queue_first_cs_timestamp(etm, etmq, i);
		if (ret)
			return ret;
	}

	while (1) {
		if (!etm->heap.heap_cnt)
			break;

		/* Take the entry at the top of the min heap */
		cs_queue_nr = etm->heap.heap_array[0].queue_nr;
		queue_nr = TO_QUEUE_NR(cs_queue_nr);
		trace_chan_id = TO_TRACE_CHAN_ID(cs_queue_nr);
		queue = &etm->queues.queue_array[queue_nr];
		etmq = queue->priv;

		/*
		 * Remove the top entry from the heap since we are about
		 * to process it.
		 */
		auxtrace_heap__pop(&etm->heap);

		tidq  = cs_etm__etmq_get_traceid_queue(etmq, trace_chan_id);
		if (!tidq) {
			/*
			 * No traceID queue has been allocated for this traceID,
			 * which means something somewhere went very wrong.  No
			 * other choice than simply exit.
			 */
			ret = -EINVAL;
			goto out;
		}

		/*
		 * Packets associated with this timestamp are already in
		 * the etmq's traceID queue, so process them.
		 */
		ret = cs_etm__process_traceid_queue(etmq, tidq);
		if (ret < 0)
			goto out;

		/*
		 * Packets for this timestamp have been processed, time to
		 * move on to the next timestamp, fetching a new auxtrace_buffer
		 * if need be.
		 */
refetch:
		ret = cs_etm__get_data_block(etmq);
		if (ret < 0)
			goto out;

		/*
		 * No more auxtrace_buffers to process in this etmq, simply
		 * move on to another entry in the auxtrace_heap.
		 */
		if (!ret)
			continue;

		ret = cs_etm__decode_data_block(etmq);
		if (ret)
			goto out;

		cs_timestamp = cs_etm__etmq_get_timestamp(etmq, &trace_chan_id);

		if (!cs_timestamp) {
			/*
			 * Function cs_etm__decode_data_block() returns when
			 * there is no more traces to decode in the current
			 * auxtrace_buffer OR when a timestamp has been
			 * encountered on any of the traceID queues.  Since we
			 * did not get a timestamp, there is no more traces to
			 * process in this auxtrace_buffer.  As such empty and
			 * flush all traceID queues.
			 */
			cs_etm__clear_all_traceid_queues(etmq);

			/* Fetch another auxtrace_buffer for this etmq */
			goto refetch;
		}

		/*
		 * Add to the min heap the timestamp for packets that have
		 * just been decoded.  They will be processed and synthesized
		 * during the next call to cs_etm__process_traceid_queue() for
		 * this queue/traceID.
		 */
		cs_queue_nr = TO_CS_QUEUE_NR(queue_nr, trace_chan_id);
		ret = auxtrace_heap__add(&etm->heap, cs_queue_nr, cs_timestamp);
	}

	for (i = 0; i < etm->queues.nr_queues; i++) {
		struct int_node *inode;

		etmq = etm->queues.queue_array[i].priv;
		if (!etmq)
			continue;

		intlist__for_each_entry(inode, etmq->traceid_queues_list) {
			int idx = (int)(intptr_t)inode->priv;

			/* Flush any remaining branch stack entries */
			tidq = etmq->traceid_queues[idx];
			ret = cs_etm__end_block(etmq, tidq);
			if (ret)
				return ret;
		}
	}
out:
	return ret;
}

static int cs_etm__process_itrace_start(struct cs_etm_auxtrace *etm,
					union perf_event *event)
{
	struct thread *th;

	if (etm->timeless_decoding)
		return 0;

	/*
	 * Add the tid/pid to the log so that we can get a match when we get a
	 * contextID from the decoder. Only track for the host: only kernel
	 * trace is supported for guests which wouldn't need pids so this should
	 * be fine.
	 */
	th = machine__findnew_thread(&etm->session->machines.host,
				     event->itrace_start.pid,
				     event->itrace_start.tid);
	if (!th)
		return -ENOMEM;

	thread__put(th);

	return 0;
}

static int cs_etm__process_switch_cpu_wide(struct cs_etm_auxtrace *etm,
					   union perf_event *event)
{
	struct thread *th;
	bool out = event->header.misc & PERF_RECORD_MISC_SWITCH_OUT;

	/*
	 * Context switch in per-thread mode are irrelevant since perf
	 * will start/stop tracing as the process is scheduled.
	 */
	if (etm->timeless_decoding)
		return 0;

	/*
	 * SWITCH_IN events carry the next process to be switched out while
	 * SWITCH_OUT events carry the process to be switched in.  As such
	 * we don't care about IN events.
	 */
	if (!out)
		return 0;

	/*
	 * Add the tid/pid to the log so that we can get a match when we get a
	 * contextID from the decoder. Only track for the host: only kernel
	 * trace is supported for guests which wouldn't need pids so this should
	 * be fine.
	 */
	th = machine__findnew_thread(&etm->session->machines.host,
				     event->context_switch.next_prev_pid,
				     event->context_switch.next_prev_tid);
	if (!th)
		return -ENOMEM;

	thread__put(th);

	return 0;
}

static int cs_etm__process_event(struct perf_session *session,
				 union perf_event *event,
				 struct perf_sample *sample,
				 struct perf_tool *tool)
{
	struct cs_etm_auxtrace *etm = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);

	if (dump_trace)
		return 0;

	if (!tool->ordered_events) {
		pr_err("CoreSight ETM Trace requires ordered events\n");
		return -EINVAL;
	}

	switch (event->header.type) {
	case PERF_RECORD_EXIT:
		/*
		 * Don't need to wait for cs_etm__flush_events() in per-thread mode to
		 * start the decode because we know there will be no more trace from
		 * this thread. All this does is emit samples earlier than waiting for
		 * the flush in other modes, but with timestamps it makes sense to wait
		 * for flush so that events from different threads are interleaved
		 * properly.
		 */
		if (etm->per_thread_decoding && etm->timeless_decoding)
			return cs_etm__process_timeless_queues(etm,
							       event->fork.tid);
		break;

	case PERF_RECORD_ITRACE_START:
		return cs_etm__process_itrace_start(etm, event);

	case PERF_RECORD_SWITCH_CPU_WIDE:
		return cs_etm__process_switch_cpu_wide(etm, event);

	case PERF_RECORD_AUX:
		/*
		 * Record the latest kernel timestamp available in the header
		 * for samples so that synthesised samples occur from this point
		 * onwards.
		 */
		if (sample->time && (sample->time != (u64)-1))
			etm->latest_kernel_timestamp = sample->time;
		break;

	default:
		break;
	}

	return 0;
}

static void dump_queued_data(struct cs_etm_auxtrace *etm,
			     struct perf_record_auxtrace *event)
{
	struct auxtrace_buffer *buf;
	unsigned int i;
	/*
	 * Find all buffers with same reference in the queues and dump them.
	 * This is because the queues can contain multiple entries of the same
	 * buffer that were split on aux records.
	 */
	for (i = 0; i < etm->queues.nr_queues; ++i)
		list_for_each_entry(buf, &etm->queues.queue_array[i].head, list)
			if (buf->reference == event->reference)
				cs_etm__dump_event(etm->queues.queue_array[i].priv, buf);
}

static int cs_etm__process_auxtrace_event(struct perf_session *session,
					  union perf_event *event,
					  struct perf_tool *tool __maybe_unused)
{
	struct cs_etm_auxtrace *etm = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);
	if (!etm->data_queued) {
		struct auxtrace_buffer *buffer;
		off_t  data_offset;
		int fd = perf_data__fd(session->data);
		bool is_pipe = perf_data__is_pipe(session->data);
		int err;
		int idx = event->auxtrace.idx;

		if (is_pipe)
			data_offset = 0;
		else {
			data_offset = lseek(fd, 0, SEEK_CUR);
			if (data_offset == -1)
				return -errno;
		}

		err = auxtrace_queues__add_event(&etm->queues, session,
						 event, data_offset, &buffer);
		if (err)
			return err;

		/*
		 * Knowing if the trace is formatted or not requires a lookup of
		 * the aux record so only works in non-piped mode where data is
		 * queued in cs_etm__queue_aux_records(). Always assume
		 * formatted in piped mode (true).
		 */
		err = cs_etm__setup_queue(etm, &etm->queues.queue_array[idx],
					  idx, true, -1);
		if (err)
			return err;

		if (dump_trace)
			if (auxtrace_buffer__get_data(buffer, fd)) {
				cs_etm__dump_event(etm->queues.queue_array[idx].priv, buffer);
				auxtrace_buffer__put_data(buffer);
			}
	} else if (dump_trace)
		dump_queued_data(etm, &event->auxtrace);

	return 0;
}

static int cs_etm__setup_timeless_decoding(struct cs_etm_auxtrace *etm)
{
	struct evsel *evsel;
	struct evlist *evlist = etm->session->evlist;

	/* Override timeless mode with user input from --itrace=Z */
	if (etm->synth_opts.timeless_decoding) {
		etm->timeless_decoding = true;
		return 0;
	}

	/*
	 * Find the cs_etm evsel and look at what its timestamp setting was
	 */
	evlist__for_each_entry(evlist, evsel)
		if (cs_etm__evsel_is_auxtrace(etm->session, evsel)) {
			etm->timeless_decoding =
				!(evsel->core.attr.config & BIT(ETM_OPT_TS));
			return 0;
		}

	pr_err("CS ETM: Couldn't find ETM evsel\n");
	return -EINVAL;
}

/*
 * Read a single cpu parameter block from the auxtrace_info priv block.
 *
 * For version 1 there is a per cpu nr_params entry. If we are handling
 * version 1 file, then there may be less, the same, or more params
 * indicated by this value than the compile time number we understand.
 *
 * For a version 0 info block, there are a fixed number, and we need to
 * fill out the nr_param value in the metadata we create.
 */
static u64 *cs_etm__create_meta_blk(u64 *buff_in, int *buff_in_offset,
				    int out_blk_size, int nr_params_v0)
{
	u64 *metadata = NULL;
	int hdr_version;
	int nr_in_params, nr_out_params, nr_cmn_params;
	int i, k;

	metadata = zalloc(sizeof(*metadata) * out_blk_size);
	if (!metadata)
		return NULL;

	/* read block current index & version */
	i = *buff_in_offset;
	hdr_version = buff_in[CS_HEADER_VERSION];

	if (!hdr_version) {
	/* read version 0 info block into a version 1 metadata block  */
		nr_in_params = nr_params_v0;
		metadata[CS_ETM_MAGIC] = buff_in[i + CS_ETM_MAGIC];
		metadata[CS_ETM_CPU] = buff_in[i + CS_ETM_CPU];
		metadata[CS_ETM_NR_TRC_PARAMS] = nr_in_params;
		/* remaining block params at offset +1 from source */
		for (k = CS_ETM_COMMON_BLK_MAX_V1 - 1; k < nr_in_params; k++)
			metadata[k + 1] = buff_in[i + k];
		/* version 0 has 2 common params */
		nr_cmn_params = 2;
	} else {
	/* read version 1 info block - input and output nr_params may differ */
		/* version 1 has 3 common params */
		nr_cmn_params = 3;
		nr_in_params = buff_in[i + CS_ETM_NR_TRC_PARAMS];

		/* if input has more params than output - skip excess */
		nr_out_params = nr_in_params + nr_cmn_params;
		if (nr_out_params > out_blk_size)
			nr_out_params = out_blk_size;

		for (k = CS_ETM_MAGIC; k < nr_out_params; k++)
			metadata[k] = buff_in[i + k];

		/* record the actual nr params we copied */
		metadata[CS_ETM_NR_TRC_PARAMS] = nr_out_params - nr_cmn_params;
	}

	/* adjust in offset by number of in params used */
	i += nr_in_params + nr_cmn_params;
	*buff_in_offset = i;
	return metadata;
}

/**
 * Puts a fragment of an auxtrace buffer into the auxtrace queues based
 * on the bounds of aux_event, if it matches with the buffer that's at
 * file_offset.
 *
 * Normally, whole auxtrace buffers would be added to the queue. But we
 * want to reset the decoder for every PERF_RECORD_AUX event, and the decoder
 * is reset across each buffer, so splitting the buffers up in advance has
 * the same effect.
 */
static int cs_etm__queue_aux_fragment(struct perf_session *session, off_t file_offset, size_t sz,
				      struct perf_record_aux *aux_event, struct perf_sample *sample)
{
	int err;
	char buf[PERF_SAMPLE_MAX_SIZE];
	union perf_event *auxtrace_event_union;
	struct perf_record_auxtrace *auxtrace_event;
	union perf_event auxtrace_fragment;
	__u64 aux_offset, aux_size;
	__u32 idx;
	bool formatted;

	struct cs_etm_auxtrace *etm = container_of(session->auxtrace,
						   struct cs_etm_auxtrace,
						   auxtrace);

	/*
	 * There should be a PERF_RECORD_AUXTRACE event at the file_offset that we got
	 * from looping through the auxtrace index.
	 */
	err = perf_session__peek_event(session, file_offset, buf,
				       PERF_SAMPLE_MAX_SIZE, &auxtrace_event_union, NULL);
	if (err)
		return err;
	auxtrace_event = &auxtrace_event_union->auxtrace;
	if (auxtrace_event->header.type != PERF_RECORD_AUXTRACE)
		return -EINVAL;

	if (auxtrace_event->header.size < sizeof(struct perf_record_auxtrace) ||
		auxtrace_event->header.size != sz) {
		return -EINVAL;
	}

	/*
	 * In per-thread mode, auxtrace CPU is set to -1, but TID will be set instead. See
	 * auxtrace_mmap_params__set_idx(). However, the sample AUX event will contain a
	 * CPU as we set this always for the AUX_OUTPUT_HW_ID event.
	 * So now compare only TIDs if auxtrace CPU is -1, and CPUs if auxtrace CPU is not -1.
	 * Return 'not found' if mismatch.
	 */
	if (auxtrace_event->cpu == (__u32) -1) {
		etm->per_thread_decoding = true;
		if (auxtrace_event->tid != sample->tid)
			return 1;
	} else if (auxtrace_event->cpu != sample->cpu) {
		if (etm->per_thread_decoding) {
			/*
			 * Found a per-cpu buffer after a per-thread one was
			 * already found
			 */
			pr_err("CS ETM: Inconsistent per-thread/per-cpu mode.\n");
			return -EINVAL;
		}
		return 1;
	}

	if (aux_event->flags & PERF_AUX_FLAG_OVERWRITE) {
		/*
		 * Clamp size in snapshot mode. The buffer size is clamped in
		 * __auxtrace_mmap__read() for snapshots, so the aux record size doesn't reflect
		 * the buffer size.
		 */
		aux_size = min(aux_event->aux_size, auxtrace_event->size);

		/*
		 * In this mode, the head also points to the end of the buffer so aux_offset
		 * needs to have the size subtracted so it points to the beginning as in normal mode
		 */
		aux_offset = aux_event->aux_offset - aux_size;
	} else {
		aux_size = aux_event->aux_size;
		aux_offset = aux_event->aux_offset;
	}

	if (aux_offset >= auxtrace_event->offset &&
	    aux_offset + aux_size <= auxtrace_event->offset + auxtrace_event->size) {
		/*
		 * If this AUX event was inside this buffer somewhere, create a new auxtrace event
		 * based on the sizes of the aux event, and queue that fragment.
		 */
		auxtrace_fragment.auxtrace = *auxtrace_event;
		auxtrace_fragment.auxtrace.size = aux_size;
		auxtrace_fragment.auxtrace.offset = aux_offset;
		file_offset += aux_offset - auxtrace_event->offset + auxtrace_event->header.size;

		pr_debug3("CS ETM: Queue buffer size: %#"PRI_lx64" offset: %#"PRI_lx64
			  " tid: %d cpu: %d\n", aux_size, aux_offset, sample->tid, sample->cpu);
		err = auxtrace_queues__add_event(&etm->queues, session, &auxtrace_fragment,
						 file_offset, NULL);
		if (err)
			return err;

		idx = auxtrace_event->idx;
		formatted = !(aux_event->flags & PERF_AUX_FLAG_CORESIGHT_FORMAT_RAW);
		return cs_etm__setup_queue(etm, &etm->queues.queue_array[idx],
					   idx, formatted, sample->cpu);
	}

	/* Wasn't inside this buffer, but there were no parse errors. 1 == 'not found' */
	return 1;
}

static int cs_etm__process_aux_hw_id_cb(struct perf_session *session, union perf_event *event,
					u64 offset __maybe_unused, void *data __maybe_unused)
{
	/* look to handle PERF_RECORD_AUX_OUTPUT_HW_ID early to ensure decoders can be set up */
	if (event->header.type == PERF_RECORD_AUX_OUTPUT_HW_ID) {
		(*(int *)data)++; /* increment found count */
		return cs_etm__process_aux_output_hw_id(session, event);
	}
	return 0;
}

static int cs_etm__queue_aux_records_cb(struct perf_session *session, union perf_event *event,
					u64 offset __maybe_unused, void *data __maybe_unused)
{
	struct perf_sample sample;
	int ret;
	struct auxtrace_index_entry *ent;
	struct auxtrace_index *auxtrace_index;
	struct evsel *evsel;
	size_t i;

	/* Don't care about any other events, we're only queuing buffers for AUX events */
	if (event->header.type != PERF_RECORD_AUX)
		return 0;

	if (event->header.size < sizeof(struct perf_record_aux))
		return -EINVAL;

	/* Truncated Aux records can have 0 size and shouldn't result in anything being queued. */
	if (!event->aux.aux_size)
		return 0;

	/*
	 * Parse the sample, we need the sample_id_all data that comes after the event so that the
	 * CPU or PID can be matched to an AUXTRACE buffer's CPU or PID.
	 */
	evsel = evlist__event2evsel(session->evlist, event);
	if (!evsel)
		return -EINVAL;
	ret = evsel__parse_sample(evsel, event, &sample);
	if (ret)
		return ret;

	/*
	 * Loop through the auxtrace index to find the buffer that matches up with this aux event.
	 */
	list_for_each_entry(auxtrace_index, &session->auxtrace_index, list) {
		for (i = 0; i < auxtrace_index->nr; i++) {
			ent = &auxtrace_index->entries[i];
			ret = cs_etm__queue_aux_fragment(session, ent->file_offset,
							 ent->sz, &event->aux, &sample);
			/*
			 * Stop search on error or successful values. Continue search on
			 * 1 ('not found')
			 */
			if (ret != 1)
				return ret;
		}
	}

	/*
	 * Couldn't find the buffer corresponding to this aux record, something went wrong. Warn but
	 * don't exit with an error because it will still be possible to decode other aux records.
	 */
	pr_err("CS ETM: Couldn't find auxtrace buffer for aux_offset: %#"PRI_lx64
	       " tid: %d cpu: %d\n", event->aux.aux_offset, sample.tid, sample.cpu);
	return 0;
}

static int cs_etm__queue_aux_records(struct perf_session *session)
{
	struct auxtrace_index *index = list_first_entry_or_null(&session->auxtrace_index,
								struct auxtrace_index, list);
	if (index && index->nr > 0)
		return perf_session__peek_events(session, session->header.data_offset,
						 session->header.data_size,
						 cs_etm__queue_aux_records_cb, NULL);

	/*
	 * We would get here if there are no entries in the index (either no auxtrace
	 * buffers or no index at all). Fail silently as there is the possibility of
	 * queueing them in cs_etm__process_auxtrace_event() if etm->data_queued is still
	 * false.
	 *
	 * In that scenario, buffers will not be split by AUX records.
	 */
	return 0;
}

#define HAS_PARAM(j, type, param) (metadata[(j)][CS_ETM_NR_TRC_PARAMS] <= \
				  (CS_##type##_##param - CS_ETM_COMMON_BLK_MAX_V1))

/*
 * Loop through the ETMs and complain if we find at least one where ts_source != 1 (virtual
 * timestamps).
 */
static bool cs_etm__has_virtual_ts(u64 **metadata, int num_cpu)
{
	int j;

	for (j = 0; j < num_cpu; j++) {
		switch (metadata[j][CS_ETM_MAGIC]) {
		case __perf_cs_etmv4_magic:
			if (HAS_PARAM(j, ETMV4, TS_SOURCE) || metadata[j][CS_ETMV4_TS_SOURCE] != 1)
				return false;
			break;
		case __perf_cs_ete_magic:
			if (HAS_PARAM(j, ETE, TS_SOURCE) || metadata[j][CS_ETE_TS_SOURCE] != 1)
				return false;
			break;
		default:
			/* Unknown / unsupported magic number. */
			return false;
		}
	}
	return true;
}

/* map trace ids to correct metadata block, from information in metadata */
static int cs_etm__map_trace_ids_metadata(int num_cpu, u64 **metadata)
{
	u64 cs_etm_magic;
	u8 trace_chan_id;
	int i, err;

	for (i = 0; i < num_cpu; i++) {
		cs_etm_magic = metadata[i][CS_ETM_MAGIC];
		switch (cs_etm_magic) {
		case __perf_cs_etmv3_magic:
			metadata[i][CS_ETM_ETMTRACEIDR] &= CORESIGHT_TRACE_ID_VAL_MASK;
			trace_chan_id = (u8)(metadata[i][CS_ETM_ETMTRACEIDR]);
			break;
		case __perf_cs_etmv4_magic:
		case __perf_cs_ete_magic:
			metadata[i][CS_ETMV4_TRCTRACEIDR] &= CORESIGHT_TRACE_ID_VAL_MASK;
			trace_chan_id = (u8)(metadata[i][CS_ETMV4_TRCTRACEIDR]);
			break;
		default:
			/* unknown magic number */
			return -EINVAL;
		}
		err = cs_etm__map_trace_id(trace_chan_id, metadata[i]);
		if (err)
			return err;
	}
	return 0;
}

/*
 * If we found AUX_HW_ID packets, then set any metadata marked as unused to the
 * unused value to reduce the number of unneeded decoders created.
 */
static int cs_etm__clear_unused_trace_ids_metadata(int num_cpu, u64 **metadata)
{
	u64 cs_etm_magic;
	int i;

	for (i = 0; i < num_cpu; i++) {
		cs_etm_magic = metadata[i][CS_ETM_MAGIC];
		switch (cs_etm_magic) {
		case __perf_cs_etmv3_magic:
			if (metadata[i][CS_ETM_ETMTRACEIDR] & CORESIGHT_TRACE_ID_UNUSED_FLAG)
				metadata[i][CS_ETM_ETMTRACEIDR] = CORESIGHT_TRACE_ID_UNUSED_VAL;
			break;
		case __perf_cs_etmv4_magic:
		case __perf_cs_ete_magic:
			if (metadata[i][CS_ETMV4_TRCTRACEIDR] & CORESIGHT_TRACE_ID_UNUSED_FLAG)
				metadata[i][CS_ETMV4_TRCTRACEIDR] = CORESIGHT_TRACE_ID_UNUSED_VAL;
			break;
		default:
			/* unknown magic number */
			return -EINVAL;
		}
	}
	return 0;
}

int cs_etm__process_auxtrace_info_full(union perf_event *event,
				       struct perf_session *session)
{
	struct perf_record_auxtrace_info *auxtrace_info = &event->auxtrace_info;
	struct cs_etm_auxtrace *etm = NULL;
	struct perf_record_time_conv *tc = &session->time_conv;
	int event_header_size = sizeof(struct perf_event_header);
	int total_size = auxtrace_info->header.size;
	int priv_size = 0;
	int num_cpu;
	int err = 0;
	int aux_hw_id_found;
	int i, j;
	u64 *ptr = NULL;
	u64 **metadata = NULL;

	/*
	 * Create an RB tree for traceID-metadata tuple.  Since the conversion
	 * has to be made for each packet that gets decoded, optimizing access
	 * in anything other than a sequential array is worth doing.
	 */
	traceid_list = intlist__new(NULL);
	if (!traceid_list)
		return -ENOMEM;

	/* First the global part */
	ptr = (u64 *) auxtrace_info->priv;
	num_cpu = ptr[CS_PMU_TYPE_CPUS] & 0xffffffff;
	metadata = zalloc(sizeof(*metadata) * num_cpu);
	if (!metadata) {
		err = -ENOMEM;
		goto err_free_traceid_list;
	}

	/* Start parsing after the common part of the header */
	i = CS_HEADER_VERSION_MAX;

	/*
	 * The metadata is stored in the auxtrace_info section and encodes
	 * the configuration of the ARM embedded trace macrocell which is
	 * required by the trace decoder to properly decode the trace due
	 * to its highly compressed nature.
	 */
	for (j = 0; j < num_cpu; j++) {
		if (ptr[i] == __perf_cs_etmv3_magic) {
			metadata[j] =
				cs_etm__create_meta_blk(ptr, &i,
							CS_ETM_PRIV_MAX,
							CS_ETM_NR_TRC_PARAMS_V0);
		} else if (ptr[i] == __perf_cs_etmv4_magic) {
			metadata[j] =
				cs_etm__create_meta_blk(ptr, &i,
							CS_ETMV4_PRIV_MAX,
							CS_ETMV4_NR_TRC_PARAMS_V0);
		} else if (ptr[i] == __perf_cs_ete_magic) {
			metadata[j] = cs_etm__create_meta_blk(ptr, &i, CS_ETE_PRIV_MAX, -1);
		} else {
			ui__error("CS ETM Trace: Unrecognised magic number %#"PRIx64". File could be from a newer version of perf.\n",
				  ptr[i]);
			err = -EINVAL;
			goto err_free_metadata;
		}

		if (!metadata[j]) {
			err = -ENOMEM;
			goto err_free_metadata;
		}
	}

	/*
	 * Each of CS_HEADER_VERSION_MAX, CS_ETM_PRIV_MAX and
	 * CS_ETMV4_PRIV_MAX mark how many double words are in the
	 * global metadata, and each cpu's metadata respectively.
	 * The following tests if the correct number of double words was
	 * present in the auxtrace info section.
	 */
	priv_size = total_size - event_header_size - INFO_HEADER_SIZE;
	if (i * 8 != priv_size) {
		err = -EINVAL;
		goto err_free_metadata;
	}

	etm = zalloc(sizeof(*etm));

	if (!etm) {
		err = -ENOMEM;
		goto err_free_metadata;
	}

	/*
	 * As all the ETMs run at the same exception level, the system should
	 * have the same PID format crossing CPUs.  So cache the PID format
	 * and reuse it for sequential decoding.
	 */
	etm->pid_fmt = cs_etm__init_pid_fmt(metadata[0]);

	err = auxtrace_queues__init(&etm->queues);
	if (err)
		goto err_free_etm;

	if (session->itrace_synth_opts->set) {
		etm->synth_opts = *session->itrace_synth_opts;
	} else {
		itrace_synth_opts__set_default(&etm->synth_opts,
				session->itrace_synth_opts->default_no_sample);
		etm->synth_opts.callchain = false;
	}

	etm->session = session;

	etm->num_cpu = num_cpu;
	etm->pmu_type = (unsigned int) ((ptr[CS_PMU_TYPE_CPUS] >> 32) & 0xffffffff);
	etm->snapshot_mode = (ptr[CS_ETM_SNAPSHOT] != 0);
	etm->metadata = metadata;
	etm->auxtrace_type = auxtrace_info->type;

	if (etm->synth_opts.use_timestamp)
		/*
		 * Prior to Armv8.4, Arm CPUs don't support FEAT_TRF feature,
		 * therefore the decoder cannot know if the timestamp trace is
		 * same with the kernel time.
		 *
		 * If a user has knowledge for the working platform and can
		 * specify itrace option 'T' to tell decoder to forcely use the
		 * traced timestamp as the kernel time.
		 */
		etm->has_virtual_ts = true;
	else
		/* Use virtual timestamps if all ETMs report ts_source = 1 */
		etm->has_virtual_ts = cs_etm__has_virtual_ts(metadata, num_cpu);

	if (!etm->has_virtual_ts)
		ui__warning("Virtual timestamps are not enabled, or not supported by the traced system.\n"
			    "The time field of the samples will not be set accurately.\n"
			    "For Arm CPUs prior to Armv8.4 or without support FEAT_TRF,\n"
			    "you can specify the itrace option 'T' for timestamp decoding\n"
			    "if the Coresight timestamp on the platform is same with the kernel time.\n\n");

	etm->auxtrace.process_event = cs_etm__process_event;
	etm->auxtrace.process_auxtrace_event = cs_etm__process_auxtrace_event;
	etm->auxtrace.flush_events = cs_etm__flush_events;
	etm->auxtrace.free_events = cs_etm__free_events;
	etm->auxtrace.free = cs_etm__free;
	etm->auxtrace.evsel_is_auxtrace = cs_etm__evsel_is_auxtrace;
	session->auxtrace = &etm->auxtrace;

	err = cs_etm__setup_timeless_decoding(etm);
	if (err)
		return err;

	etm->tc.time_shift = tc->time_shift;
	etm->tc.time_mult = tc->time_mult;
	etm->tc.time_zero = tc->time_zero;
	if (event_contains(*tc, time_cycles)) {
		etm->tc.time_cycles = tc->time_cycles;
		etm->tc.time_mask = tc->time_mask;
		etm->tc.cap_user_time_zero = tc->cap_user_time_zero;
		etm->tc.cap_user_time_short = tc->cap_user_time_short;
	}
	err = cs_etm__synth_events(etm, session);
	if (err)
		goto err_free_queues;

	/*
	 * Map Trace ID values to CPU metadata.
	 *
	 * Trace metadata will always contain Trace ID values from the legacy algorithm. If the
	 * files has been recorded by a "new" perf updated to handle AUX_HW_ID then the metadata
	 * ID value will also have the CORESIGHT_TRACE_ID_UNUSED_FLAG set.
	 *
	 * The updated kernel drivers that use AUX_HW_ID to sent Trace IDs will attempt to use
	 * the same IDs as the old algorithm as far as is possible, unless there are clashes
	 * in which case a different value will be used. This means an older perf may still
	 * be able to record and read files generate on a newer system.
	 *
	 * For a perf able to interpret AUX_HW_ID packets we first check for the presence of
	 * those packets. If they are there then the values will be mapped and plugged into
	 * the metadata. We then set any remaining metadata values with the used flag to a
	 * value CORESIGHT_TRACE_ID_UNUSED_VAL - which indicates no decoder is required.
	 *
	 * If no AUX_HW_ID packets are present - which means a file recorded on an old kernel
	 * then we map Trace ID values to CPU directly from the metadata - clearing any unused
	 * flags if present.
	 */

	/* first scan for AUX_OUTPUT_HW_ID records to map trace ID values to CPU metadata */
	aux_hw_id_found = 0;
	err = perf_session__peek_events(session, session->header.data_offset,
					session->header.data_size,
					cs_etm__process_aux_hw_id_cb, &aux_hw_id_found);
	if (err)
		goto err_free_queues;

	/* if HW ID found then clear any unused metadata ID values */
	if (aux_hw_id_found)
		err = cs_etm__clear_unused_trace_ids_metadata(num_cpu, metadata);
	/* otherwise, this is a file with metadata values only, map from metadata */
	else
		err = cs_etm__map_trace_ids_metadata(num_cpu, metadata);

	if (err)
		goto err_free_queues;

	err = cs_etm__queue_aux_records(session);
	if (err)
		goto err_free_queues;

	etm->data_queued = etm->queues.populated;
	return 0;

err_free_queues:
	auxtrace_queues__free(&etm->queues);
	session->auxtrace = NULL;
err_free_etm:
	zfree(&etm);
err_free_metadata:
	/* No need to check @metadata[j], free(NULL) is supported */
	for (j = 0; j < num_cpu; j++)
		zfree(&metadata[j]);
	zfree(&metadata);
err_free_traceid_list:
	intlist__delete(traceid_list);
	return err;
}
