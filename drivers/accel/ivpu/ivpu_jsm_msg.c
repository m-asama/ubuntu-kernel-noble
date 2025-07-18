// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020-2023 Intel Corporation
 */

#include "ivpu_drv.h"
#include "ivpu_hw.h"
#include "ivpu_ipc.h"
#include "ivpu_jsm_msg.h"

const char *ivpu_jsm_msg_type_to_str(enum vpu_ipc_msg_type type)
{
	#define IVPU_CASE_TO_STR(x) case x: return #x
	switch (type) {
	IVPU_CASE_TO_STR(VPU_JSM_MSG_UNKNOWN);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_ENGINE_RESET);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_ENGINE_PREEMPT);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_REGISTER_DB);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_UNREGISTER_DB);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_QUERY_ENGINE_HB);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_GET_POWER_LEVEL_COUNT);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_GET_POWER_LEVEL);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_SET_POWER_LEVEL);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_OPEN);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_CLOSE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_TRACE_SET_CONFIG);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_TRACE_GET_CONFIG);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_TRACE_GET_CAPABILITY);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_TRACE_GET_NAME);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_SSID_RELEASE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_START);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_STOP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_UPDATE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_INFO);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_SET_PRIORITY_BAND_SETUP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_CREATE_CMD_QUEUE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_DESTROY_CMD_QUEUE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_SET_CONTEXT_SCHED_PROPERTIES);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_HWS_REGISTER_DB);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_HWS_RESUME_CMDQ);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_HWS_SUSPEND_CMDQ);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_HWS_RESUME_CMDQ_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_HWS_SUSPEND_CMDQ_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_HWS_SET_SCHEDULING_LOG);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_HWS_SET_SCHEDULING_LOG_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_HWS_SCHEDULING_LOG_NOTIFICATION);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_HWS_ENGINE_RESUME);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_HWS_RESUME_ENGINE_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_STATE_DUMP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_STATE_DUMP_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_BLOB_DEINIT);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_DYNDBG_CONTROL);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_JOB_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_ENGINE_RESET_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_ENGINE_PREEMPT_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_REGISTER_DB_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_UNREGISTER_DB_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_QUERY_ENGINE_HB_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_GET_POWER_LEVEL_COUNT_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_GET_POWER_LEVEL_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_SET_POWER_LEVEL_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_OPEN_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_CLOSE_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_TRACE_SET_CONFIG_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_TRACE_GET_CONFIG_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_TRACE_GET_CAPABILITY_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_TRACE_GET_NAME_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_SSID_RELEASE_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_START_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_STOP_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_UPDATE_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_INFO_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_METRIC_STREAMER_NOTIFICATION);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_SET_PRIORITY_BAND_SETUP_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_CREATE_CMD_QUEUE_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_DESTROY_CMD_QUEUE_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_SET_CONTEXT_SCHED_PROPERTIES_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_BLOB_DEINIT_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_DYNDBG_CONTROL_RSP);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_PWR_D0I3_ENTER);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_PWR_D0I3_ENTER_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_DCT_ENABLE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_DCT_ENABLE_DONE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_DCT_DISABLE);
	IVPU_CASE_TO_STR(VPU_JSM_MSG_DCT_DISABLE_DONE);
	}
	#undef IVPU_CASE_TO_STR

	return "Unknown JSM message type";
}

int ivpu_jsm_register_db(struct ivpu_device *vdev, u32 ctx_id, u32 db_id,
			 u64 jobq_base, u32 jobq_size)
{
	struct vpu_jsm_msg req = { .type = VPU_JSM_MSG_REGISTER_DB };
	struct vpu_jsm_msg resp;
	int ret = 0;

	req.payload.register_db.db_idx = db_id;
	req.payload.register_db.jobq_base = jobq_base;
	req.payload.register_db.jobq_size = jobq_size;
	req.payload.register_db.host_ssid = ctx_id;

	ret = ivpu_ipc_send_receive(vdev, &req, VPU_JSM_MSG_REGISTER_DB_DONE, &resp,
				    VPU_IPC_CHAN_ASYNC_CMD, vdev->timeout.jsm);
	if (ret) {
		ivpu_err_ratelimited(vdev, "Failed to register doorbell %d: %d\n", db_id, ret);
		return ret;
	}

	ivpu_dbg(vdev, JSM, "Doorbell %d registered to context %d\n", db_id, ctx_id);

	return 0;
}

int ivpu_jsm_unregister_db(struct ivpu_device *vdev, u32 db_id)
{
	struct vpu_jsm_msg req = { .type = VPU_JSM_MSG_UNREGISTER_DB };
	struct vpu_jsm_msg resp;
	int ret = 0;

	req.payload.unregister_db.db_idx = db_id;

	ret = ivpu_ipc_send_receive(vdev, &req, VPU_JSM_MSG_UNREGISTER_DB_DONE, &resp,
				    VPU_IPC_CHAN_ASYNC_CMD, vdev->timeout.jsm);
	if (ret) {
		ivpu_warn_ratelimited(vdev, "Failed to unregister doorbell %d: %d\n", db_id, ret);
		return ret;
	}

	ivpu_dbg(vdev, JSM, "Doorbell %d unregistered\n", db_id);

	return 0;
}

int ivpu_jsm_get_heartbeat(struct ivpu_device *vdev, u32 engine, u64 *heartbeat)
{
	struct vpu_jsm_msg req = { .type = VPU_JSM_MSG_QUERY_ENGINE_HB };
	struct vpu_jsm_msg resp;
	int ret;

	if (engine > VPU_ENGINE_COPY)
		return -EINVAL;

	req.payload.query_engine_hb.engine_idx = engine;

	ret = ivpu_ipc_send_receive(vdev, &req, VPU_JSM_MSG_QUERY_ENGINE_HB_DONE, &resp,
				    VPU_IPC_CHAN_ASYNC_CMD, vdev->timeout.jsm);
	if (ret) {
		ivpu_err_ratelimited(vdev, "Failed to get heartbeat from engine %d: %d\n",
				     engine, ret);
		return ret;
	}

	*heartbeat = resp.payload.query_engine_hb_done.heartbeat;
	return ret;
}

int ivpu_jsm_reset_engine(struct ivpu_device *vdev, u32 engine)
{
	struct vpu_jsm_msg req = { .type = VPU_JSM_MSG_ENGINE_RESET };
	struct vpu_jsm_msg resp;
	int ret;

	if (engine > VPU_ENGINE_COPY)
		return -EINVAL;

	req.payload.engine_reset.engine_idx = engine;

	ret = ivpu_ipc_send_receive(vdev, &req, VPU_JSM_MSG_ENGINE_RESET_DONE, &resp,
				    VPU_IPC_CHAN_ASYNC_CMD, vdev->timeout.jsm);
	if (ret)
		ivpu_err_ratelimited(vdev, "Failed to reset engine %d: %d\n", engine, ret);

	return ret;
}

int ivpu_jsm_preempt_engine(struct ivpu_device *vdev, u32 engine, u32 preempt_id)
{
	struct vpu_jsm_msg req = { .type = VPU_JSM_MSG_ENGINE_PREEMPT };
	struct vpu_jsm_msg resp;
	int ret;

	if (engine > VPU_ENGINE_COPY)
		return -EINVAL;

	req.payload.engine_preempt.engine_idx = engine;
	req.payload.engine_preempt.preempt_id = preempt_id;

	ret = ivpu_ipc_send_receive(vdev, &req, VPU_JSM_MSG_ENGINE_PREEMPT_DONE, &resp,
				    VPU_IPC_CHAN_ASYNC_CMD, vdev->timeout.jsm);
	if (ret)
		ivpu_err_ratelimited(vdev, "Failed to preempt engine %d: %d\n", engine, ret);

	return ret;
}

int ivpu_jsm_dyndbg_control(struct ivpu_device *vdev, char *command, size_t size)
{
	struct vpu_jsm_msg req = { .type = VPU_JSM_MSG_DYNDBG_CONTROL };
	struct vpu_jsm_msg resp;
	int ret;

	strscpy(req.payload.dyndbg_control.dyndbg_cmd, command, VPU_DYNDBG_CMD_MAX_LEN);

	ret = ivpu_ipc_send_receive(vdev, &req, VPU_JSM_MSG_DYNDBG_CONTROL_RSP, &resp,
				    VPU_IPC_CHAN_ASYNC_CMD, vdev->timeout.jsm);
	if (ret)
		ivpu_warn_ratelimited(vdev, "Failed to send command \"%s\": ret %d\n",
				      command, ret);

	return ret;
}

int ivpu_jsm_trace_get_capability(struct ivpu_device *vdev, u32 *trace_destination_mask,
				  u64 *trace_hw_component_mask)
{
	struct vpu_jsm_msg req = { .type = VPU_JSM_MSG_TRACE_GET_CAPABILITY };
	struct vpu_jsm_msg resp;
	int ret;

	ret = ivpu_ipc_send_receive(vdev, &req, VPU_JSM_MSG_TRACE_GET_CAPABILITY_RSP, &resp,
				    VPU_IPC_CHAN_ASYNC_CMD, vdev->timeout.jsm);
	if (ret) {
		ivpu_warn_ratelimited(vdev, "Failed to get trace capability: %d\n", ret);
		return ret;
	}

	*trace_destination_mask = resp.payload.trace_capability.trace_destination_mask;
	*trace_hw_component_mask = resp.payload.trace_capability.trace_hw_component_mask;

	return ret;
}

int ivpu_jsm_trace_set_config(struct ivpu_device *vdev, u32 trace_level, u32 trace_destination_mask,
			      u64 trace_hw_component_mask)
{
	struct vpu_jsm_msg req = { .type = VPU_JSM_MSG_TRACE_SET_CONFIG };
	struct vpu_jsm_msg resp;
	int ret;

	req.payload.trace_config.trace_level = trace_level;
	req.payload.trace_config.trace_destination_mask = trace_destination_mask;
	req.payload.trace_config.trace_hw_component_mask = trace_hw_component_mask;

	ret = ivpu_ipc_send_receive(vdev, &req, VPU_JSM_MSG_TRACE_SET_CONFIG_RSP, &resp,
				    VPU_IPC_CHAN_ASYNC_CMD, vdev->timeout.jsm);
	if (ret)
		ivpu_warn_ratelimited(vdev, "Failed to set config: %d\n", ret);

	return ret;
}

int ivpu_jsm_context_release(struct ivpu_device *vdev, u32 host_ssid)
{
	struct vpu_jsm_msg req = { .type = VPU_JSM_MSG_SSID_RELEASE };
	struct vpu_jsm_msg resp;

	req.payload.ssid_release.host_ssid = host_ssid;

	return ivpu_ipc_send_receive(vdev, &req, VPU_JSM_MSG_SSID_RELEASE_DONE, &resp,
				     VPU_IPC_CHAN_ASYNC_CMD, vdev->timeout.jsm);
}

int ivpu_jsm_pwr_d0i3_enter(struct ivpu_device *vdev)
{
	struct vpu_jsm_msg req = { .type = VPU_JSM_MSG_PWR_D0I3_ENTER };
	struct vpu_jsm_msg resp;
	int ret;

	if (IVPU_WA(disable_d0i3_msg))
		return 0;

	req.payload.pwr_d0i3_enter.send_response = 1;

	ret = ivpu_ipc_send_receive_internal(vdev, &req, VPU_JSM_MSG_PWR_D0I3_ENTER_DONE, &resp,
					     VPU_IPC_CHAN_GEN_CMD, vdev->timeout.d0i3_entry_msg);
	if (ret)
		return ret;

	return ivpu_hw_wait_for_idle(vdev);
}
