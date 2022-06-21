// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Microsoft Corporation.
 *
 * An implementation of a cfg80211 driver that delegates control operations to a
 * proxy through a VSock. The data path is redirected to an ethernet net_device
 * similarly as in virt_wifi.
 *
 * Author: guhetier@microsoft.com
 */

#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <linux/math64.h>
#include <linux/module.h>

#include <linux/list.h>
#include <linux/vm_sockets.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/sockptr.h>
#include <linux/time_types.h>

/* Ports must be in host byte order */
#define PROXY_WIFI_REQUEST_PORT 12345
#define PROXY_WIFI_NOTIFICATION_PORT 12346

enum proxy_wifi_operation {
	WIFI_INVALID = 0,
	WIFI_OP_SCAN_REQUEST = 1,
	WIFI_OP_SCAN_RESPONSE,
	WIFI_OP_CONNECT_REQUEST,
	WIFI_OP_CONNECT_RESPONSE,
	WIFI_OP_DISCONNECT_REQUEST,
	WIFI_OP_DISCONNECT_RESPONSE,
	WIFI_NOTIF_DISCONNECTED,
	WIFI_NOTIF_SIGNAL_QUALITY,
	WIFI_OP_MAX
};

enum proxy_wifi_version {
	VERSION_0_1 = 0x0001,
};

struct proxy_wifi_hdr {
	/* An enum proxy_wifi_operation value */
	u8 operation;
	u32 size;
	/* An enum proxy_wifi_version value */
	u16 version;
} __packed;

struct proxy_wifi_bss {
	u8 bssid[ETH_ALEN];
	u16 capabilities;
	u32 rssi;
	u16 beacon_interval;
	u32 channel_center_freq;
	u32 ie_size;
	u32 ie_offset;
} __packed;

struct proxy_wifi_scan_request {
	u8 ssid_len;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
} __packed;

struct proxy_wifi_scan_response {
	u8 scan_complete;
	u32 num_bss;
	u32 total_size;
	struct proxy_wifi_bss bss[];
} __packed;

struct proxy_wifi_connect_request {
	u8 ssid_len;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 bssid[ETH_ALEN];
	u8 auth_type;
	u8 wpa_versions;
	u8 num_akm_suites;
	u32 akm_suites[NL80211_MAX_NR_AKM_SUITES];
	u8 num_pairwise_cipher_suites;
	u32 pairwise_cipher_suites[NL80211_MAX_NR_CIPHER_SUITES];
	u32 group_cipher_suite;
	u8 key_len;
	u8 key[];
} __packed;

struct proxy_wifi_connect_response {
	u16 result_code;
	u8 bssid[ETH_ALEN];
	u64 session_id;
} __packed;

struct proxy_wifi_disconnect_request {
	u64 session_id;
} __packed;

struct proxy_wifi_disconnect_notif {
	u64 session_id;
} __packed;

struct proxy_wifi_signal_quality_notif {
	s8 signal;
} __packed;

struct proxy_wifi_msg {
	struct list_head link;
	struct proxy_wifi_hdr hdr;
	u8 *body;
};

/* ------------- Driver private context ------------ */

/* Lock to protect the proxy_wifi context */
DEFINE_RWLOCK(proxy_wifi_context_lock);

/* Lock to protect access to the notification queue */
DEFINE_SPINLOCK(proxy_wifi_notif_lock);

struct connection_state {
	u32 tx_packets;
	u32 tx_failed;
	/* Protected by `proxy_wifi_context_lock` */
	u8 bssid[ETH_ALEN];
	/* Protected by `proxy_wifi_context_lock` */
	bool is_connected;
	/* Protected by `proxy_wifi_context_lock` */
	s8 signal;
	/* Protected by `proxy_wifi_context_lock` */
	u64 session_id;
};

struct proxy_wifi_netdev_priv {
	struct net_device *lowerdev;
	struct net_device *upperdev;

	struct work_struct connect;
	struct work_struct disconnect;

	struct proxy_wifi_connect_request *connect_req_ctx;

	/* Protected by `proxy_wifi_context_lock` */
	u16 disconnect_reason;

	/* Protected by `proxy_wifi_context_lock` */
	bool is_up;
	/* Protected by rtnl lock */
	bool being_deleted;
	struct connection_state connection;
};

struct proxy_wifi_wiphy_priv {
	struct work_struct handle_notif;
	struct task_struct *notif_thread;

	/* Protected by `proxy_wifi_notif_lock */
	struct list_head pending_notifs;

	struct work_struct scan_result;
	struct delayed_work scan_timeout;
	/* Not protected but access are sequentials */
	struct cfg80211_scan_request *scan_request;
	struct socket *notification_socket;

	unsigned int request_port;
	unsigned int notification_port;

	/* Protectd by `proxy_wifi_context_lock` */
	bool being_deleted;

	/* Protectd by `proxy_wifi_context_lock` */
	struct net_device *netdev;

	/* Single threaded workqueue to serialize all exchanges with the host */
	struct workqueue_struct *workqueue;
};

static struct wiphy *common_wiphy;

/* ------------- Message builder functions ------------ */

static int
build_scan_request_msg(struct proxy_wifi_msg *message,
		       const struct cfg80211_scan_request *scan_params)
{
	struct proxy_wifi_scan_request *scan_request = NULL;

	message->hdr.operation = WIFI_OP_SCAN_REQUEST;
	message->hdr.size = sizeof(struct proxy_wifi_scan_request);
	message->hdr.version = VERSION_0_1;

	message->body = kzalloc(message->hdr.size, GFP_KERNEL);
	if (!message->body)
		return -ENOMEM;

	if (scan_params->n_ssids > 0) {
		scan_request = (struct proxy_wifi_scan_request *)message->body;
		scan_request->ssid_len = scan_params->ssids[0].ssid_len;
		memcpy(scan_request->ssid, scan_params->ssids[0].ssid,
		       sizeof(scan_request->ssid));
	}
	return 0;
}

static int
build_connect_request_msg(struct proxy_wifi_msg *message,
			  const struct proxy_wifi_connect_request *conn_params)
{
	message->hdr.operation = WIFI_OP_CONNECT_REQUEST;
	message->hdr.size = sizeof(struct proxy_wifi_connect_request) +
			    conn_params->key_len;
	message->hdr.version = VERSION_0_1;

	message->body = kzalloc(message->hdr.size, GFP_KERNEL);
	if (!message->body)
		return -ENOMEM;

	memcpy(message->body, conn_params, message->hdr.size);
	return 0;
}

static int build_disconnect_request_msg(struct proxy_wifi_msg *message,
					u64 session_id)
{
	struct proxy_wifi_disconnect_request *disconnect_request = NULL;

	message->hdr.operation = WIFI_OP_DISCONNECT_REQUEST;
	message->hdr.size = sizeof(struct proxy_wifi_disconnect_request);
	message->hdr.version = VERSION_0_1;

	message->body = kzalloc(message->hdr.size, GFP_KERNEL);
	if (!message->body)
		return -ENOMEM;

	disconnect_request =
		(struct proxy_wifi_disconnect_request *)message->body;
	disconnect_request->session_id = session_id;

	return 0;
}

/* --------------- Message sending functions --------------- */

static int receive_bytes(struct socket *socket, size_t expected_size,
			 u8 *buffer)
{
	int return_code = 0;
	size_t total_received = 0;
	struct msghdr msg_header = { 0 };
	struct kvec iv = { .iov_len = expected_size, .iov_base = buffer };

	while (total_received < expected_size) {
		return_code = kernel_recvmsg(socket, &msg_header, &iv, 1,
					     expected_size - total_received, 0);
		if (return_code <= 0)
			return return_code;

		total_received += return_code;
		if (total_received > expected_size)
			return -EINVAL;

		iv.iov_len = expected_size - total_received;
		iv.iov_base = (u8 *)buffer + total_received;
	}

	return 0;
}

static int receive_proxy_wifi_message(struct socket *socket,
				      struct proxy_wifi_msg *message)
{
	int error = 0;

	error = receive_bytes(socket, sizeof(message->hdr),
			      (u8 *)&message->hdr);
	if (error < 0)
		return error;

	pr_debug("proxy_wifi: Receiving a message (Operation: %d, %d bytes)",
		 message->hdr.operation, message->hdr.size);

	kfree(message->body);
	message->body = NULL;

	if (message->hdr.size > 0) {
		message->body = kzalloc(message->hdr.size, GFP_KERNEL);
		if (!message->body)
			return -ENOMEM;

		error = receive_bytes(socket, message->hdr.size, message->body);
		if (error < 0)
			goto out_free;
	}

	if (message->hdr.version != VERSION_0_1) {
		pr_err("Receive message with unsupported version %d",
		       message->hdr.version);
		error = -EINVAL;
		goto out_free;
	}

	return 0;

out_free:
	kfree(message->body);
	message->body = NULL;
	return error;
}

static int send_bytes(struct socket *socket, size_t message_size, u8 *buffer)
{
	int return_code = 0;
	size_t total_sent = 0;
	struct msghdr msg_header = { 0 };
	struct kvec iv = { .iov_len = message_size, .iov_base = buffer };

	while (total_sent < message_size) {
		return_code = kernel_sendmsg(socket, &msg_header, &iv, 1,
					     message_size - total_sent);

		if (return_code < 0)
			return return_code;
		if (return_code == 0)
			return -EINVAL;

		total_sent += return_code;
		if (total_sent > message_size)
			return -EINVAL;

		iv.iov_len = message_size - total_sent;
		iv.iov_base = (u8 *)buffer + total_sent;
		return_code = 0;
	}

	return 0;
}

static int send_proxy_wifi_message(struct socket *socket,
				   struct proxy_wifi_msg *message)
{
	int error = 0;

	if (!message->body && message->hdr.size != 0)
		return -EINVAL;

	pr_debug("proxy_wifi: Sending a message (Operation: %d, %d bytes)",
		 message->hdr.operation, message->hdr.size);

	error = send_bytes(socket, sizeof(message->hdr), (u8 *)&message->hdr);
	if (error < 0)
		return error;

	error = send_bytes(socket, message->hdr.size, message->body);
	if (error < 0)
		return error;

	return 0;
}

static int query_host(struct proxy_wifi_msg *message, unsigned int port)
{
	int error = 0;
	struct socket *socket = NULL;
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_port = port,
		.svm_cid = VMADDR_CID_HOST,
	};
	/* The socket will wait for a response until the corresponding operation
	 * completed on the host: the timeout needs to be large enough for long
	 * operations (connect) to complete.
	 */
	struct __kernel_sock_timeval timeout = { .tv_sec = 20, .tv_usec = 0}; /* 20s */
	sockptr_t timeout_ptr = { .kernel = &timeout, .is_kernel = true };

	error = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &socket);
	if (error != 0) {
		pr_err("proxy_wifi: Failed to create a socket, error %d",
		       error);
		return error;
	}

	error = kernel_connect(socket, (struct sockaddr *)&addr, sizeof(addr),
			       0);
	if (error != 0) {
		pr_err("proxy_wifi: Failed to connect to the host, error %d",
		       error);
		goto out_sock_release;
	}

	error = sock_setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO_NEW,
				timeout_ptr, sizeof(timeout));
	if (error != 0) {
		pr_err("proxy_wifi: Failed to set a send timeout on the request socket, error %d",
		       error);
		goto out_sock_release;
	}
	error = sock_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO_NEW,
				timeout_ptr, sizeof(timeout));
	if (error != 0) {
		pr_err("proxy_wifi: Failed to set a receive timeout on the request socket, error %d",
		       error);
		goto out_sock_release;
	}

	error = send_proxy_wifi_message(socket, message);
	if (error < 0) {
		pr_err("proxy_wifi: Failed to send message, error %d", error);
		goto out_sock_release;
	}

	error = receive_proxy_wifi_message(socket, message);
	if (error < 0) {
		pr_err("proxy_wifi: Failed to receive an answer, error %d",
		       error);
		goto out_sock_release;
	}

	error = 0;

out_sock_release:
	sock_release(socket);
	return error;
}

static struct proxy_wifi_msg
scan_command(unsigned int port,
	     const struct cfg80211_scan_request *scan_request)
{
	int error = 0;
	struct proxy_wifi_msg message = { 0 };

	pr_info("proxy_wifi: Sending SCAN request to host");

	error = build_scan_request_msg(&message, scan_request);
	if (error != 0) {
		pr_err("proxy_wifi: Failed to build a scan request");
		goto error;
	}

	error = query_host(&message, port);
	if (error != 0)
		goto error;

	return message;

error:
	kfree(message.body);
	message.body = NULL;
	message.hdr.size = 0;
	message.hdr.operation = WIFI_INVALID;
	return message;
}

static struct proxy_wifi_msg
connect_command(unsigned int port,
		const struct proxy_wifi_connect_request *connection_params)
{
	int error = 0;
	struct proxy_wifi_msg message = { 0 };

	pr_info("proxy_wifi: Sending CONNECT request to host");

	error = build_connect_request_msg(&message, connection_params);

	if (error != 0) {
		pr_err("proxy_wifi: Failed to build a connect request message");
		goto error;
	}

	error = query_host(&message, port);
	if (error != 0)
		goto error;

	return message;

error:
	kfree(message.body);
	message.body = NULL;
	message.hdr.size = 0;
	message.hdr.operation = WIFI_INVALID;
	return message;
}

static struct proxy_wifi_msg disconnect_command(unsigned int port,
						u64 session_id)
{
	int error = 0;
	struct proxy_wifi_msg message = { 0 };

	pr_info("proxy_wifi: Sending DISCONNECT request to host");

	error = build_disconnect_request_msg(&message, session_id);

	if (error != 0) {
		pr_err("proxy_wifi: Failed to build a connect request message");
		goto error;
	}

	error = query_host(&message, port);
	if (error != 0)
		goto error;

	return message;

error:
	kfree(message.body);
	message.body = NULL;
	message.hdr.size = 0;
	message.hdr.operation = WIFI_INVALID;
	return message;
}

/* ---- Notification queue ---- */

static void list_queue_msg(struct proxy_wifi_msg *msg, struct list_head *list)
{
	list_add_tail(&msg->link, list);
}

static struct proxy_wifi_msg *list_pop_msg(struct list_head *list)
{
	struct proxy_wifi_msg *msg = NULL;

	msg = list_first_entry_or_null(list, struct proxy_wifi_msg, link);
	if (msg)
		list_del_init(&msg->link);
	return msg;
}

static void list_clear_msg(struct list_head *list)
{
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	struct proxy_wifi_msg *msg = NULL;

	list_for_each_safe(pos, n, list) {
		list_del(pos);
		msg = list_entry(pos, struct proxy_wifi_msg, link);
		kfree(msg->body);
		kfree(msg);
	}
}

static void queue_notification(struct proxy_wifi_wiphy_priv *w_priv,
			       struct proxy_wifi_msg *msg)
{
	spin_lock(&proxy_wifi_notif_lock);
	list_queue_msg(msg, &w_priv->pending_notifs);
	spin_unlock(&proxy_wifi_notif_lock);
	queue_work(w_priv->workqueue, &w_priv->handle_notif);
}

static struct proxy_wifi_msg *
pop_notification(struct proxy_wifi_wiphy_priv *w_priv)
{
	struct proxy_wifi_msg *msg = NULL;

	spin_lock(&proxy_wifi_notif_lock);
	msg = list_pop_msg(&w_priv->pending_notifs);
	spin_unlock(&proxy_wifi_notif_lock);
	return msg;
}

static void flush_notifications(struct proxy_wifi_wiphy_priv *w_priv)
{
	cancel_work_sync(&w_priv->handle_notif);

	spin_lock(&proxy_wifi_notif_lock);
	list_clear_msg(&w_priv->pending_notifs);
	spin_unlock(&proxy_wifi_notif_lock);
}

/* ---- Notification handling ---- */

static void proxy_wifi_disconnect_finalize(struct net_device *netdev,
					   u16 reason_code);

static void
handle_disconnected_notification(struct proxy_wifi_wiphy_priv *w_priv,
				 struct proxy_wifi_msg message)
{
	struct wiphy *wiphy = priv_to_wiphy(w_priv);
	struct proxy_wifi_netdev_priv *n_priv = NULL;
	struct proxy_wifi_disconnect_notif *disconnect_notif = NULL;
	u64 session_id = 0;

	read_lock(&proxy_wifi_context_lock);
	if (w_priv->netdev) {
		n_priv = netdev_priv(w_priv->netdev);
		session_id = n_priv->connection.session_id;
	}
	read_unlock(&proxy_wifi_context_lock);

	if (!n_priv) {
		wiphy_debug(wiphy,
			    "proxy_wifi: Dropping a disconnected notification, no active netdevice\n");
		return;
	}

	netdev_info(n_priv->upperdev,
		    "proxy_wifi: Handling a disconnected notification\n");

	if (message.hdr.size != sizeof(struct proxy_wifi_disconnect_notif))
		netdev_warn(n_priv->upperdev,
			    "proxy_wifi: Unexpected size for a disconnect notification: %d bytes\n",
			    message.hdr.size);

	disconnect_notif = (struct proxy_wifi_disconnect_notif *)message.body;

	if (disconnect_notif->session_id < session_id) {
		netdev_warn(n_priv->upperdev,
			    "proxy_wifi: Ignoring an outdated disconnect notification. Notification session: %lld, current session: %lld\n",
			    disconnect_notif->session_id, session_id);
		return;
	}

	proxy_wifi_disconnect_finalize(n_priv->upperdev, WLAN_REASON_UNSPECIFIED);
}

static void
handle_signal_quality_notification(struct proxy_wifi_wiphy_priv *w_priv,
				   struct proxy_wifi_msg message)
{
	struct wiphy *wiphy = priv_to_wiphy(w_priv);
	struct proxy_wifi_netdev_priv *n_priv = NULL;
	struct proxy_wifi_signal_quality_notif *signal_notif = NULL;

	read_lock(&proxy_wifi_context_lock);
	if (w_priv->netdev)
		n_priv = netdev_priv(w_priv->netdev);
	read_unlock(&proxy_wifi_context_lock);

	if (!n_priv) {
		wiphy_debug(wiphy,
			    "proxy_wifi: Dropping a signal quality notification, no active netdevice\n");
		return;
	}
	netdev_dbg(n_priv->upperdev,
		   "proxy_wifi: Handling a signal quality notification\n");

	if (message.hdr.size !=
		    sizeof(struct proxy_wifi_signal_quality_notif) ||
	    !message.body) {
		netdev_err(n_priv->upperdev,
			   "proxy_wifi: Invalid size for a signal quality notification: %d bytes\n",
			   message.hdr.size);
		return;
	}
	signal_notif = (struct proxy_wifi_signal_quality_notif *)message.body;

	write_lock(&proxy_wifi_context_lock);
	n_priv->connection.signal = signal_notif->signal;
	write_unlock(&proxy_wifi_context_lock);
}

static bool is_bss_valid(const struct proxy_wifi_bss *bss,
			 const struct proxy_wifi_msg *message)
{
	/* Check the bss and its IEs are contained in the message body */
	return (u8 *)bss >= message->body &&
	       (u8 *)bss + bss->ie_offset + bss->ie_size <=
		       (u8 *)message->body + message->hdr.size;
}

static int report_scanned_network(struct wiphy *wiphy,
				  struct proxy_wifi_bss *bss)
{
	struct cfg80211_bss *informed_bss = NULL;
	const u64 tsf = div_u64(ktime_get_boottime_ns(), 1000);
	struct ieee80211_channel *channel = NULL;

	channel = ieee80211_get_channel_khz(wiphy, bss->channel_center_freq);
	if (!channel) {
		wiphy_warn(wiphy,
			   "proxy_wifi: Unsupported frequency %d, ignoring scan result\n",
			   bss->channel_center_freq);
		return -EINVAL;
	}

	informed_bss =
		cfg80211_inform_bss(wiphy, channel, CFG80211_BSS_FTYPE_PRESP,
				    bss->bssid, tsf, bss->capabilities,
				    bss->beacon_interval,
				    (u8 *)bss + bss->ie_offset, bss->ie_size,
				    bss->rssi * 100, /* rssi expected in mBm */
				    GFP_KERNEL);

	cfg80211_put_bss(wiphy, informed_bss);
	return 0;
}

static void
handle_scan_results_notification(struct proxy_wifi_wiphy_priv *w_priv,
				 struct proxy_wifi_msg message)
{
	struct wiphy *wiphy = priv_to_wiphy(w_priv);
	struct proxy_wifi_scan_response *scan_response = NULL;
	struct cfg80211_scan_request *scan_request = NULL;
	int i = 0;
	struct proxy_wifi_bss *bss = NULL;
	struct cfg80211_scan_info scan_info = { .aborted = false };

	wiphy_info(wiphy,
		   "proxy_wifi: Handling a scan_response notification\n");

	if (message.hdr.size < sizeof(struct proxy_wifi_scan_response) ||
	    !message.body) {
		wiphy_err(wiphy,
			  "proxy_wifi: Invalid size for a scan results notification: %d bytes\n",
			  message.hdr.size);
		return;
	}
	scan_response = (struct proxy_wifi_scan_response *)message.body;

	wiphy_info(wiphy, "proxy_wifi: Received %u scan results\n",
		   scan_response->num_bss);

	for (i = 0; i < scan_response->num_bss; i++) {
		bss = &scan_response->bss[i];
		if (!is_bss_valid(bss, &message)) {
			wiphy_warn(wiphy,
				   "proxy_wifi: Ignoring an invalid scan result (Index %d)",
				   i);
			continue;
		}

		report_scanned_network(wiphy, &scan_response->bss[i]);
	}

	/* Complete the scan request if needed */
	if (scan_response->scan_complete) {
		write_lock(&proxy_wifi_context_lock);
		scan_request = w_priv->scan_request;
		w_priv->scan_request = NULL;
		write_unlock(&proxy_wifi_context_lock);

		if (scan_request) {
			/* Schedules work which acquires and releases the rtnl lock. */
			cfg80211_scan_done(scan_request, &scan_info);
			cancel_delayed_work_sync(&w_priv->scan_timeout);
		}
	}
}

static void proxy_wifi_handle_notifications(struct work_struct *work)
{
	struct proxy_wifi_msg *msg = NULL;
	struct proxy_wifi_wiphy_priv *w_priv =
		container_of(work, struct proxy_wifi_wiphy_priv, handle_notif);
	struct wiphy *wiphy = priv_to_wiphy(w_priv);

	for (;;) {
		msg = pop_notification(w_priv);
		if (!msg)
			/* No more notifications to process */
			return;

		/* Dispatch the notification */
		if (msg->hdr.operation == WIFI_NOTIF_DISCONNECTED)
			handle_disconnected_notification(w_priv, *msg);
		else if (msg->hdr.operation == WIFI_NOTIF_SIGNAL_QUALITY)
			handle_signal_quality_notification(w_priv, *msg);
		else if (msg->hdr.operation == WIFI_OP_SCAN_RESPONSE)
			handle_scan_results_notification(w_priv, *msg);
		else
			wiphy_warn(wiphy,
				   "proxy_wifi: Received an unknown notification\n");
		kfree(msg->body);
		kfree(msg);
	}
}

static int receive_notification(struct proxy_wifi_wiphy_priv *w_priv,
				struct socket *socket)
{
	int error = 0;
	struct wiphy *wiphy = priv_to_wiphy(w_priv);
	struct proxy_wifi_msg *msg = NULL;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	error = receive_proxy_wifi_message(socket, msg);
	if (error < 0) {
		wiphy_err(wiphy,
			  "proxy_wifi: Failed to receive a notification, error %d\n",
			  error);
		kfree(msg);
		return error;
	}

	wiphy_dbg(wiphy, "proxy_wifi: Got a notification, type %d\n",
		  msg->hdr.operation);

	/* Queue the notif to handle it synchronously by the workqueue */
	queue_notification(w_priv, msg);
	return 0;
}

static int create_listening_socket(int port, struct socket **listen_socket)
{
	int error = 0;
	struct sockaddr_vm addr = { .svm_family = AF_VSOCK,
				    .svm_port = port,
				    .svm_cid = VMADDR_CID_ANY };
	struct __kernel_sock_timeval timeout = {0, 10000}; /* 10 ms */
	sockptr_t timeout_ptr = { .kernel = &timeout, .is_kernel = true };
	struct socket *socket;

	*listen_socket = NULL;
	error = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &socket);
	if (error != 0) {
		pr_err("proxy_wifi: Failed to create the notification socket, error %d",
		       error);
		return error;
	}

	error = sock_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO_NEW,
				timeout_ptr, sizeof(timeout));
	if (error != 0) {
		pr_err("proxy_wifi: Failed to set a timeout on the notification socket, error %d",
		       error);
		goto out_release_sock;
	}

	error = kernel_bind(socket, (struct sockaddr *)&addr, sizeof(addr));
	if (error != 0) {
		pr_err("proxy_wifi: Failed to bind the notification socket, error %d",
		       error);
		goto out_release_sock;
	}

	error = kernel_listen(socket, INT_MAX);
	if (error != 0) {
		pr_err("proxy_wifi: Failed to listen on the notification socket, error %d",
		       error);
		goto out_release_sock;
	}

	*listen_socket = socket;
	return 0;

out_release_sock:
	sock_release(socket);
	return error;
}

static int accept_notification(struct proxy_wifi_wiphy_priv *w_priv)
{
	int error = 0;
	struct wiphy *wiphy = priv_to_wiphy(w_priv);
	struct socket *accept_socket = NULL;
	struct __kernel_sock_timeval timeout = { 0, 10000 }; /* 10 ms */
	sockptr_t timeout_ptr = { .kernel = &timeout, .is_kernel = true };

	error = kernel_accept(w_priv->notification_socket, &accept_socket, 0);
	if (error == -EAGAIN) {
		return 0;
	} else if (error != 0) {
		wiphy_err(wiphy,
			  "proxy_wifi: Failed to accept a connection, error %d",
			  error);
		return error;
	}

	error = sock_setsockopt(accept_socket, SOL_SOCKET, SO_RCVTIMEO_NEW,
				timeout_ptr, sizeof(timeout));
	if (error != 0) {
		pr_err("proxy_wifi: Failed to set a timeout on the notification socket, error %d",
		       error);
		goto out_release_sock;
	}

	error = receive_notification(w_priv, accept_socket);
	if (error != 0) {
		wiphy_warn(wiphy,
			   "proxy_wifi: Failed to receive a notification, error %d",
			   error);
		// Ignore this error, we can still handle next notifications
		error = 0;
		goto out_release_sock;
	}

out_release_sock:
	kernel_sock_shutdown(accept_socket, SHUT_RDWR);
	sock_release(accept_socket);
	accept_socket = NULL;
	return error;
}

static int listen_notifications(void *context)
{
	int error = 0;
	struct proxy_wifi_wiphy_priv *w_priv = context;

	while (!kthread_should_stop()) {
		error = accept_notification(w_priv);
		if (error != 0)
			break;
	}

	return error;
}

static int
setup_notification_channel(struct proxy_wifi_wiphy_priv *w_priv)
{
	int err = 0;
	struct task_struct *thread_res = NULL;
	struct wiphy *wiphy = priv_to_wiphy(w_priv);

	err = create_listening_socket(w_priv->notification_port,
				      &w_priv->notification_socket);
	if (err != 0)
		return err;

	/* Start the notification handling thread */
	thread_res = kthread_create(listen_notifications, w_priv,
				    "proxy_wifi notif");
	if (IS_ERR(thread_res)) {
		err = PTR_ERR(thread_res);
		wiphy_err(wiphy,
			  "proxy_wifi: Failed to create the notif thread, error %d",
			  err);
		goto out_release_sock;
	}

	w_priv->notif_thread = ERR_CAST(thread_res);
	/* `put_task_struct` in `stop_notification_channel`.
	 * Keeep the task_struct alive until `kthread_stop` if the thread exit early
	 */
	get_task_struct(w_priv->notif_thread);
	wake_up_process(w_priv->notif_thread);
	return 0;

out_release_sock:
	sock_release(w_priv->notification_socket);
	w_priv->notification_socket = NULL;
	return err;
}

static void
stop_notification_channel(struct proxy_wifi_wiphy_priv *w_priv)
{
	struct wiphy *wiphy = priv_to_wiphy(w_priv);

	if (w_priv->notif_thread) {
		wiphy_dbg(wiphy,
			  "proxy_wifi: Waiting for notification thread completion...");
		kthread_stop(w_priv->notif_thread);
		put_task_struct(w_priv->notif_thread);
		w_priv->notif_thread = NULL;
	}

	if (w_priv->notification_socket) {
		sock_release(w_priv->notification_socket);
		w_priv->notification_socket = NULL;
	}

	flush_notifications(w_priv);
}

/* ---- Driver config data ---- */

static const u32 cipher_suites[] = {
	WLAN_CIPHER_SUITE_CCMP,		WLAN_CIPHER_SUITE_GCMP,
	WLAN_CIPHER_SUITE_CCMP_256,	WLAN_CIPHER_SUITE_GCMP_256,
	WLAN_CIPHER_SUITE_AES_CMAC,	WLAN_CIPHER_SUITE_BIP_GMAC_128,
	WLAN_CIPHER_SUITE_BIP_CMAC_256, WLAN_CIPHER_SUITE_BIP_GMAC_256,
	WLAN_CIPHER_SUITE_TKIP
};

static const u32 akm_suites[] = { WLAN_AKM_SUITE_PSK, WLAN_AKM_SUITE_SAE };

static struct ieee80211_channel channels_2ghz[] = {
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2412, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2417, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2422, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2427, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2432, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2437, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2442, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2447, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2452, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2457, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2462, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2467, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2472, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2477, .max_power = 20, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2484, .max_power = 20, },
};

static struct ieee80211_rate bitrates_2ghz[] = {
	{ .bitrate = 10 },  { .bitrate = 20 }, { .bitrate = 55 },
	{ .bitrate = 110 }, { .bitrate = 60 }, { .bitrate = 120 },
	{ .bitrate = 240 },
};

static struct ieee80211_supported_band band_2ghz = {
	.channels = channels_2ghz,
	.bitrates = bitrates_2ghz,
	.band = NL80211_BAND_2GHZ,
	.n_channels = ARRAY_SIZE(channels_2ghz),
	.n_bitrates = ARRAY_SIZE(bitrates_2ghz),
	.ht_cap = {
		.ht_supported = true,
		.cap = IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
		       IEEE80211_HT_CAP_GRN_FLD |
		       IEEE80211_HT_CAP_SGI_20 |
		       IEEE80211_HT_CAP_SGI_40 |
		       IEEE80211_HT_CAP_DSSSCCK40,
		.ampdu_factor = 0x3,
		.ampdu_density = 0x6,
		.mcs = {
			.rx_mask = {0xff, 0xff},
			.tx_params = IEEE80211_HT_MCS_TX_DEFINED,
		},
	},
};

static struct ieee80211_channel channels_5ghz[] = {
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5160, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5170, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5180, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5190, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5200, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5210, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5220, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5230, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5240, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5250, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5260, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5270, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5280, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5290, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5300, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5310, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5320, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5340, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5480, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5500, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5510, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5520, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5530, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5540, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5550, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5560, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5570, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5580, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5590, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5600, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5610, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5620, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5630, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5640, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5660, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5670, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5680, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5690, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5700, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5710, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5720, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5745, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5755, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5765, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5775, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5785, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5795, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5805, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5815, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5825, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5835, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5845, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5855, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5865, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5875, .max_power = 20, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5885, .max_power = 20, },
};

static struct ieee80211_rate bitrates_5ghz[] = {
	{ .bitrate = 60 },
	{ .bitrate = 120 },
	{ .bitrate = 240 },
};

#define RX_MCS_MAP                                                             \
	(IEEE80211_VHT_MCS_SUPPORT_0_9 << 0 |                                  \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 2 |                                  \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 4 |                                  \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 6 |                                  \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 8 |                                  \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 10 |                                 \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 12 |                                 \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 14)

#define TX_MCS_MAP                                                             \
	(IEEE80211_VHT_MCS_SUPPORT_0_9 << 0 |                                  \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 2 |                                  \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 4 |                                  \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 6 |                                  \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 8 |                                  \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 10 |                                 \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 12 |                                 \
	 IEEE80211_VHT_MCS_SUPPORT_0_9 << 14)

static struct ieee80211_supported_band band_5ghz = {
	.channels = channels_5ghz,
	.bitrates = bitrates_5ghz,
	.band = NL80211_BAND_5GHZ,
	.n_channels = ARRAY_SIZE(channels_5ghz),
	.n_bitrates = ARRAY_SIZE(bitrates_5ghz),
	.ht_cap = {
		.ht_supported = true,
		.cap = IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
		       IEEE80211_HT_CAP_GRN_FLD |
		       IEEE80211_HT_CAP_SGI_20 |
		       IEEE80211_HT_CAP_SGI_40 |
		       IEEE80211_HT_CAP_DSSSCCK40,
		.ampdu_factor = 0x3,
		.ampdu_density = 0x6,
		.mcs = {
			.rx_mask = {0xff, 0xff},
			.tx_params = IEEE80211_HT_MCS_TX_DEFINED,
		},
	},
	.vht_cap = {
		.vht_supported = true,
		.cap = IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454 |
		       IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ |
		       IEEE80211_VHT_CAP_RXLDPC |
		       IEEE80211_VHT_CAP_SHORT_GI_80 |
		       IEEE80211_VHT_CAP_SHORT_GI_160 |
		       IEEE80211_VHT_CAP_TXSTBC |
		       IEEE80211_VHT_CAP_RXSTBC_1 |
		       IEEE80211_VHT_CAP_RXSTBC_2 |
		       IEEE80211_VHT_CAP_RXSTBC_3 |
		       IEEE80211_VHT_CAP_RXSTBC_4 |
		       IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK,
		.vht_mcs = {
			.rx_mcs_map = cpu_to_le16(RX_MCS_MAP),
			.tx_mcs_map = cpu_to_le16(TX_MCS_MAP),
		}
	},
};

static struct ieee80211_channel channels_6ghz[] = {
	{ .band = NL80211_BAND_6GHZ, .center_freq = 5955, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 5975, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 5995, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6015, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6035, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6055, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6075, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6095, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6115, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6135, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6155, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6175, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6195, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6215, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6235, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6255, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6275, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6295, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6315, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6335, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6355, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6375, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6395, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6415, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6435, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6455, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6475, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6495, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6515, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6535, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6555, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6575, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6595, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6615, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6635, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6655, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6675, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6695, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6715, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6735, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6755, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6775, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6795, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6815, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6835, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6855, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6875, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6895, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6915, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6935, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6955, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6975, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 6995, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 7015, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 7035, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 7055, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 7075, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 7095, .max_power = 20, },
	{ .band = NL80211_BAND_6GHZ, .center_freq = 7115, .max_power = 20, },
};

static struct ieee80211_rate bitrates_6ghz[] = {
	{ .bitrate = 60 },  { .bitrate = 90 },	{ .bitrate = 120 },
	{ .bitrate = 180 }, { .bitrate = 240 }, { .bitrate = 360 },
	{ .bitrate = 480 }, { .bitrate = 540 },
};

/* Taken from mac80211_hwsim. */
static const struct ieee80211_sband_iftype_data iftype_data_6ghz[] = {
	{
		.types_mask = BIT(NL80211_IFTYPE_STATION),
		.he_cap = {
			.has_he = true,
			.he_cap_elem = {
				.mac_cap_info[0] =
					IEEE80211_HE_MAC_CAP0_HTC_HE,
				.mac_cap_info[1] =
					IEEE80211_HE_MAC_CAP1_TF_MAC_PAD_DUR_16US |
					IEEE80211_HE_MAC_CAP1_MULTI_TID_AGG_RX_QOS_8,
				.mac_cap_info[2] =
					IEEE80211_HE_MAC_CAP2_BSR |
					IEEE80211_HE_MAC_CAP2_MU_CASCADING |
					IEEE80211_HE_MAC_CAP2_ACK_EN,
				.mac_cap_info[3] =
					IEEE80211_HE_MAC_CAP3_OMI_CONTROL |
					IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_VHT_2,
				.mac_cap_info[4] = IEEE80211_HE_MAC_CAP4_AMDSU_IN_AMPDU,
				.phy_cap_info[0] =
					IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G |
					IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G |
					IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G,
				.phy_cap_info[1] =
					IEEE80211_HE_PHY_CAP1_PREAMBLE_PUNC_RX_MASK |
					IEEE80211_HE_PHY_CAP1_DEVICE_CLASS_A |
					IEEE80211_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD |
					IEEE80211_HE_PHY_CAP1_MIDAMBLE_RX_TX_MAX_NSTS,
				.phy_cap_info[2] =
					IEEE80211_HE_PHY_CAP2_NDP_4x_LTF_AND_3_2US |
					IEEE80211_HE_PHY_CAP2_STBC_TX_UNDER_80MHZ |
					IEEE80211_HE_PHY_CAP2_STBC_RX_UNDER_80MHZ |
					IEEE80211_HE_PHY_CAP2_UL_MU_FULL_MU_MIMO |
					IEEE80211_HE_PHY_CAP2_UL_MU_PARTIAL_MU_MIMO,

				/* Leave all the other PHY capability bytes
				 * unset, as DCM, beam forming, RU and PPE
				 * threshold information are not supported
				 */
			},
			.he_mcs_nss_supp = {
				.rx_mcs_80 = cpu_to_le16(0xfffa),
				.tx_mcs_80 = cpu_to_le16(0xfffa),
				.rx_mcs_160 = cpu_to_le16(0xfffa),
				.tx_mcs_160 = cpu_to_le16(0xfffa),
				.rx_mcs_80p80 = cpu_to_le16(0xfffa),
				.tx_mcs_80p80 = cpu_to_le16(0xfffa),
			},
		},
	}
};

static struct ieee80211_supported_band band_6ghz = {
	.channels = channels_6ghz,
	.bitrates = bitrates_6ghz,
	.band = NL80211_BAND_6GHZ,
	.n_channels = ARRAY_SIZE(channels_6ghz),
	.n_bitrates = ARRAY_SIZE(bitrates_6ghz),
	.n_iftype_data = ARRAY_SIZE(iftype_data_6ghz),
	.iftype_data = iftype_data_6ghz
};

/* ---- 80211cfg request handling ---- */

/* Called with the rtnl lock held. */
static int proxy_wifi_scan(struct wiphy *wiphy,
			   struct cfg80211_scan_request *request)
{
	int err = 0;
	struct proxy_wifi_wiphy_priv *w_priv = wiphy_priv(wiphy);

	wiphy_info(wiphy, "proxy_wifi: Starting a scan request\n");

	write_lock(&proxy_wifi_context_lock);
	if (w_priv->scan_request || w_priv->being_deleted) {
		err = -EBUSY;
	} else {
		w_priv->scan_request = request;
		if (!queue_work(w_priv->workqueue, &w_priv->scan_result)) {
			w_priv->scan_request = NULL;
			err = -EBUSY;
		}
	}

	write_unlock(&proxy_wifi_context_lock);
	return err;
}

/* Acquires and releases the rdev BSS lock. */
static void proxy_wifi_scan_result(struct work_struct *work)
{
	struct proxy_wifi_wiphy_priv *w_priv =
		container_of(work, struct proxy_wifi_wiphy_priv, scan_result);
	struct wiphy *wiphy = priv_to_wiphy(w_priv);
	struct cfg80211_scan_request *scan_request = NULL;
	struct cfg80211_scan_info scan_info = { .aborted = false };
	struct proxy_wifi_msg message = { 0 };
	struct proxy_wifi_scan_response *scan_response = NULL;
	struct proxy_wifi_bss *bss = NULL;
	int i = 0;
	bool set_scan_done = true;

	read_lock(&proxy_wifi_context_lock);
	scan_request = w_priv->scan_request;
	read_unlock(&proxy_wifi_context_lock);

	if (!scan_request) {
		wiphy_err(wiphy,
			  "proxy_wifi: No scan parameters for a scan request\n");
		return;
	}

	message = scan_command(w_priv->request_port, scan_request);
	if (message.hdr.operation != WIFI_OP_SCAN_RESPONSE) {
		wiphy_err(wiphy,
			  "proxy_wifi: Invalid scan response (Operation: %d)\n",
			  message.hdr.operation);
		scan_info.aborted = true;
		goto complete_scan;
	}

	if (message.hdr.size < sizeof(struct proxy_wifi_scan_response)) {
		wiphy_err(wiphy,
			   "proxy_wifi: Invalid scan response (Size: %d)\n",
			   message.hdr.size);
		scan_info.aborted = true;
		goto complete_scan;
	}

	scan_response = (struct proxy_wifi_scan_response *)message.body;

	wiphy_info(wiphy, "proxy_wifi: Received %u scan results\n",
		   scan_response->num_bss);

	for (i = 0; i < scan_response->num_bss; i++) {
		bss = &scan_response->bss[i];
		if (!is_bss_valid(bss, &message)) {
			wiphy_warn(wiphy,
				   "proxy_wifi: Ignoring an invalid scan result (Index %d)",
				   i);
			continue;
		}

		report_scanned_network(wiphy, &scan_response->bss[i]);
	}

complete_scan:
	/* More results are coming from the host through a notification.
	 * Ensure the scan will be complete in 10sec.
	 */
	if (scan_response && !scan_response->scan_complete) {
		if (queue_delayed_work(w_priv->workqueue, &w_priv->scan_timeout,
				       10 * HZ))
			set_scan_done = false;
	}

	if (set_scan_done) {
		write_lock(&proxy_wifi_context_lock);
		w_priv->scan_request = NULL;
		write_unlock(&proxy_wifi_context_lock);
		/* Schedules work which acquires and releases the rtnl lock. */
		cfg80211_scan_done(scan_request, &scan_info);
	}
	kfree(message.body);
}

static void proxy_wifi_scan_timeout(struct work_struct *work)
{
	struct proxy_wifi_wiphy_priv *w_priv = container_of(work,
			       struct proxy_wifi_wiphy_priv, scan_timeout.work);
	struct wiphy *wiphy = priv_to_wiphy(w_priv);
	struct cfg80211_scan_request *scan_request = NULL;
	struct cfg80211_scan_info scan_info = { .aborted = false };

	write_lock(&proxy_wifi_context_lock);
	scan_request = w_priv->scan_request;
	w_priv->scan_request = NULL;
	write_unlock(&proxy_wifi_context_lock);

	if (scan_request) {
		wiphy_warn(wiphy, "proxy_wifi: A scan request timed out\n");
		/* Schedules work which acquires and releases the rtnl lock. */
		cfg80211_scan_done(scan_request, &scan_info);
	}
}

/* May acquire and release the rdev BSS lock. */
static void proxy_wifi_cancel_scan(struct wiphy *wiphy)
{
	struct proxy_wifi_wiphy_priv *w_priv = wiphy_priv(wiphy);
	struct cfg80211_scan_request *scan_request = NULL;
	struct cfg80211_scan_info scan_info = { .aborted = true };

	cancel_work_sync(&w_priv->scan_result);

	/* Complete the scan request if needed (scan work didn't run or async completion) */
	write_lock(&proxy_wifi_context_lock);
	scan_request = w_priv->scan_request;
	w_priv->scan_request = NULL;
	write_unlock(&proxy_wifi_context_lock);

	if (scan_request) {
		wiphy_info(wiphy, "proxy_wifi: A scan request was canceled\n");
		/* Schedules work which acquires and releases the rtnl lock. */
		cfg80211_scan_done(scan_request, &scan_info);
		cancel_delayed_work_sync(&w_priv->scan_timeout);
	}
}

/* May acquire and release the rdev BSS lock. */
static void proxy_wifi_abort_scan(struct wiphy *wiphy, struct wireless_dev *dev)
{
	wiphy_info(wiphy, "proxy_wifi: Aborting a scan request\n");
	proxy_wifi_cancel_scan(wiphy);
}

/* Called with the proxy_wifi_context_lock held */
static int
build_connect_request_cxt(struct cfg80211_connect_params *sme,
			  struct proxy_wifi_connect_request **connect_req_ctx)
{
	struct proxy_wifi_connect_request *context = NULL;
	u8 key_len = 0;
	const u8 *key = NULL;

	/* Determine which key to use and its length */
	if (sme->crypto.psk) {
		key = sme->crypto.psk;
		key_len = WLAN_PMK_LEN;
	} else if (sme->crypto.sae_pwd && sme->crypto.sae_pwd_len) {
		key = sme->crypto.sae_pwd;
		key_len = sme->crypto.sae_pwd_len;
	} else if (sme->key && sme->key_len > 0) {
		key = sme->key;
		key_len = sme->key_len;
	}

	context = kzalloc(sizeof(*context) + key_len, GFP_KERNEL);
	if (!context)
		return -ENOMEM;

	/* Get SSID */
	memcpy(context->ssid, sme->ssid, sme->ssid_len);
	context->ssid_len = sme->ssid_len;

	/* Get requested BSS if any */
	if (sme->bssid)
		/* Can't use ether_addr_copy: dest bssid not aligned to u16 */
		memcpy(context->bssid, sme->bssid, ETH_ALEN);
	else
		eth_zero_addr(context->bssid);

	/* Get security params */
	context->auth_type = sme->auth_type;
	context->wpa_versions = (u8)sme->crypto.wpa_versions;

	context->num_akm_suites = sme->crypto.n_akm_suites;
	memcpy(context->akm_suites, sme->crypto.akm_suites,
	       sme->crypto.n_akm_suites * sizeof(sme->crypto.akm_suites[0]));

	context->num_pairwise_cipher_suites = sme->crypto.n_ciphers_pairwise;
	memcpy(context->pairwise_cipher_suites, sme->crypto.ciphers_pairwise,
	       sme->crypto.n_ciphers_pairwise *
		       sizeof(sme->crypto.ciphers_pairwise[0]));

	context->group_cipher_suite = sme->crypto.cipher_group;
	context->key_len = key_len;
	memcpy(context->key, key, key_len);

	*connect_req_ctx = context;
	return 0;
}

/* Called with the rtnl lock held. */
/* Acquires and releases proxy_wifi_context_lock. */
static int proxy_wifi_connect(struct wiphy *wiphy, struct net_device *netdev,
			      struct cfg80211_connect_params *sme)
{
	int error = 0;
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(netdev);
	struct proxy_wifi_wiphy_priv *w_priv = wiphy_priv(wiphy);

	netdev_info(netdev, "proxy_wifi: Starting a connection request\n");

	write_lock(&proxy_wifi_context_lock);

	if (n_priv->being_deleted || !n_priv->is_up || n_priv->connect_req_ctx) {
		error = -EBUSY;
		goto out_release_lock;
	}

	error = build_connect_request_cxt(sme, &n_priv->connect_req_ctx);
	if (error < 0) {
		wiphy_err(wiphy,
			  "proxy_wifi: Failed to build the connect request context: %d\n",
			  error);
		goto out_release_lock;
	}

	/* Set the bssid for canceling the connection if needed */
	if (sme->bssid)
		ether_addr_copy(n_priv->connection.bssid, sme->bssid);
	else
		eth_zero_addr(n_priv->connection.bssid);

	if (!queue_work(w_priv->workqueue, &n_priv->connect)) {
		error = -EBUSY;
		kfree(n_priv->connect_req_ctx);
		n_priv->connect_req_ctx = NULL;
	}

out_release_lock:
	write_unlock(&proxy_wifi_context_lock);
	return error;
}

/* Acquires and releases the rdev event lock. */
/* Acquires and releases proxy_wifi_context_lock. */
static void proxy_wifi_connect_complete(struct work_struct *work)
{
	struct proxy_wifi_netdev_priv *n_priv =
		container_of(work, struct proxy_wifi_netdev_priv, connect);
	struct proxy_wifi_wiphy_priv *w_priv =
		(struct proxy_wifi_wiphy_priv *)
			n_priv->upperdev->ieee80211_ptr->wiphy->priv;
	u16 status = WLAN_STATUS_UNSPECIFIED_FAILURE;
	struct proxy_wifi_connect_request *connect_req_ctx = NULL;
	bool is_up = false;
	struct proxy_wifi_connect_response *connect_response = NULL;
	struct proxy_wifi_msg message = { 0 };

	write_lock(&proxy_wifi_context_lock);
	connect_req_ctx = n_priv->connect_req_ctx;
	n_priv->connect_req_ctx = NULL;
	is_up = n_priv->is_up;
	write_unlock(&proxy_wifi_context_lock);

	if (!connect_req_ctx) {
		netdev_err(n_priv->upperdev,
			   "proxy_wifi: No connection parameters for a connection request\n");
		return;
	}

	if (!is_up) {
		netdev_err(n_priv->upperdev,
			   "proxy_wifi: net_dev not up, aborting the connection request\n");
		goto complete_connect;
	}

	message = connect_command(w_priv->request_port, connect_req_ctx);

	if (message.hdr.operation != WIFI_OP_CONNECT_RESPONSE) {
		netdev_err(n_priv->upperdev,
			   "proxy_wifi: Invalid connect response (Operation: %d)\n",
			   message.hdr.operation);
		goto complete_connect;
	}

	if (message.hdr.size != sizeof(struct proxy_wifi_connect_response)) {
		netdev_err(n_priv->upperdev,
			   "proxy_wifi: Invalid connect response (Size: %d)\n",
			   message.hdr.size);
		goto complete_connect;
	}

	connect_response = (struct proxy_wifi_connect_response *)message.body;
	status = connect_response->result_code;

	netdev_info(n_priv->upperdev,
		    "proxy_wifi: Connection result: %d, session id: %lld\n",
		    status, connect_response->session_id);

	if (status == WLAN_STATUS_SUCCESS) {
		/* Set the current connection information */
		write_lock(&proxy_wifi_context_lock);
		n_priv->connection.is_connected = true;
		n_priv->connection.signal = -50;
		n_priv->connection.session_id = connect_response->session_id;
		n_priv->connection.tx_failed = 0;
		n_priv->connection.tx_packets = 0;

		/* Can't use ether_addr_copy: dest bssid not aligned to u16 */
		memcpy(n_priv->connection.bssid, connect_response->bssid,
		       sizeof(n_priv->connection.bssid));

		write_unlock(&proxy_wifi_context_lock);

		netif_carrier_on(n_priv->upperdev);
	}

complete_connect:
	/* Schedules an event that acquires the rtnl lock. */
	cfg80211_connect_result(n_priv->upperdev,
				connect_response ? connect_response->bssid :
							 connect_req_ctx->bssid,
				NULL, 0, NULL, 0, status, GFP_KERNEL);

	kfree(connect_req_ctx);
	kfree(message.body);
}

/* May acquire and release the rdev event lock. */
/* May acquire and release proxy_wifi_context_lock */
static void proxy_wifi_cancel_connect(struct net_device *netdev)
{
	u8 bssid[ETH_ALEN] = { 0 };
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(netdev);

	/* If there is work pending, clean up dangling callbacks. */
	if (cancel_work_sync(&n_priv->connect)) {
		netdev_info(netdev,
			    "proxy_wifi: A connection request was canceled\n");

		write_lock(&proxy_wifi_context_lock);
		ether_addr_copy(bssid, n_priv->connection.bssid);

		kfree(n_priv->connect_req_ctx);
		n_priv->connect_req_ctx = NULL;
		write_unlock(&proxy_wifi_context_lock);

		/* Schedules an event that acquires the rtnl lock. */
		cfg80211_connect_result(n_priv->upperdev, bssid, NULL, 0, NULL, 0,
					WLAN_STATUS_UNSPECIFIED_FAILURE,
					GFP_KERNEL);
	}
}

/* Subcall acquires the rdev event lock. */
/* Acquires and releases proxy_wifi_context_lock */
static void proxy_wifi_disconnect_finalize(struct net_device *netdev,
					   u16 reason_code)
{
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(netdev);
	bool is_connected = false;
	bool connect_rq_pending = false;

	write_lock(&proxy_wifi_context_lock);
	is_connected = n_priv->connection.is_connected;
	connect_rq_pending = !!n_priv->connect_req_ctx;
	n_priv->connection.is_connected = false;
	write_unlock(&proxy_wifi_context_lock);

	if (is_connected)
		netif_carrier_off(netdev);

	/* Don't indicate the disconnection if another connection request has
	 * been queued: it would be seen as a failure for the new request
	 */
	if (is_connected && !connect_rq_pending)
		cfg80211_disconnected(netdev, reason_code, NULL, 0, true,
				      GFP_KERNEL);
}

/* Subcall acquires the rdev event lock. */
/* Subcall acquires and releases proxy_wifi_context_lock */
static void proxy_wifi_disconnect_complete(struct work_struct *work)
{
	struct proxy_wifi_netdev_priv *n_priv =
		container_of(work, struct proxy_wifi_netdev_priv, disconnect);
	struct proxy_wifi_wiphy_priv *w_priv =
		(struct proxy_wifi_wiphy_priv *)
			n_priv->upperdev->ieee80211_ptr->wiphy->priv;
	struct proxy_wifi_msg message = { 0 };
	u64 session_id = 0;
	u16 reason;

	read_lock(&proxy_wifi_context_lock);
	session_id = n_priv->connection.session_id;
	reason = n_priv->disconnect_reason ? n_priv->disconnect_reason :
						   WLAN_REASON_UNSPECIFIED;
	n_priv->disconnect_reason = 0;
	read_unlock(&proxy_wifi_context_lock);

	message = disconnect_command(w_priv->request_port, session_id);

	netdev_info(n_priv->upperdev,
		    "proxy_wifi: Disconnected, session id %lld\n", session_id);

	/* Still complete the disconnection on error */
	if (message.hdr.operation != WIFI_OP_DISCONNECT_RESPONSE)
		netdev_err(n_priv->upperdev,
			   "proxy_wifi: Expected WIFI_OP_DISCONNECT_RESPONSE, got: %d",
			   message.hdr.operation);

	proxy_wifi_disconnect_finalize(n_priv->upperdev, reason);

	kfree(message.body);
}

/* Called with the rtnl lock held. */
/* Subcall acquires and releases the rdev event lock. */
/* Subcall acquires and releases proxy_wifi_context_lock. */
static int proxy_wifi_disconnect(struct wiphy *wiphy, struct net_device *netdev,
				 u16 reason_code)
{
	int err = 0;
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(netdev);
	struct proxy_wifi_wiphy_priv *w_priv = wiphy_priv(wiphy);

	netdev_info(netdev, "proxy_wifi: Starting a disconnect request\n");
	proxy_wifi_cancel_connect(netdev);

	write_lock(&proxy_wifi_context_lock);
	if (n_priv->being_deleted) {
		err = -EBUSY;
	} else if (n_priv->connection.is_connected) {
		n_priv->disconnect_reason = reason_code;
		if (!queue_work(w_priv->workqueue, &n_priv->disconnect)) {
			n_priv->disconnect_reason = 0;
			err = -EBUSY;
		}
	}
	write_unlock(&proxy_wifi_context_lock);

	return err;
}

/* Called with the rtnl lock held. */
/* Acquires and releases proxy_wifi_context_lock. */
static int proxy_wifi_get_station(struct wiphy *wiphy, struct net_device *dev,
				  const u8 *mac, struct station_info *sinfo)
{
	int error = 0;
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(dev);

	wiphy_dbg(wiphy, "proxy_wifi: Reporting station info\n");

	read_lock(&proxy_wifi_context_lock);

	if (!n_priv->connection.is_connected) {
		error = -ENOENT;
		goto out_unlock;
	}

	if (!ether_addr_equal(mac, n_priv->connection.bssid)) {
		error = -ENOENT;
		goto out_unlock;
	}

	sinfo->filled = BIT_ULL(NL80211_STA_INFO_TX_PACKETS) |
			BIT_ULL(NL80211_STA_INFO_TX_FAILED) |
			BIT_ULL(NL80211_STA_INFO_SIGNAL) |
			BIT_ULL(NL80211_STA_INFO_TX_BITRATE);
	sinfo->tx_packets = n_priv->connection.tx_packets;
	sinfo->tx_failed = n_priv->connection.tx_failed;
	/* For CFG80211_SIGNAL_TYPE_MBM, value is expressed in _dBm_ */
	sinfo->signal = n_priv->connection.signal;
	sinfo->txrate = (struct rate_info){
		.legacy = 5000, /* units are 100kbit/s */
	};

out_unlock:
	read_unlock(&proxy_wifi_context_lock);
	return error;
}

/* Called with the rtnl lock held. */
/* Acquires and releases proxy_wifi_context_lock. */
static int proxy_wifi_dump_station(struct wiphy *wiphy, struct net_device *dev,
				   int idx, u8 *mac, struct station_info *sinfo)
{
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(dev);
	bool is_connected = false;

	read_lock(&proxy_wifi_context_lock);
	is_connected = n_priv->connection.is_connected;
	ether_addr_copy(mac, n_priv->connection.bssid);
	read_unlock(&proxy_wifi_context_lock);

	if (idx != 0 || !is_connected)
		return -ENOENT;

	return proxy_wifi_get_station(wiphy, dev, mac, sinfo);
}

static const struct cfg80211_ops proxy_wifi_cfg80211_ops = {
	.scan = proxy_wifi_scan,
	.abort_scan = proxy_wifi_abort_scan,

	.connect = proxy_wifi_connect,
	.disconnect = proxy_wifi_disconnect,

	.get_station = proxy_wifi_get_station,
	.dump_station = proxy_wifi_dump_station,
};

/* Acquires and releases the rtnl lock. */
static struct wiphy *proxy_wifi_make_wiphy(void)
{
	struct wiphy *wiphy;
	struct proxy_wifi_wiphy_priv *w_priv;
	int err = 0;

	wiphy = wiphy_new(&proxy_wifi_cfg80211_ops, sizeof(*w_priv));

	if (!wiphy)
		return NULL;

	wiphy->max_scan_ssids = 1;
	wiphy->max_scan_ie_len = 1000;
	wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;

	wiphy->bands[NL80211_BAND_2GHZ] = &band_2ghz;
	wiphy->bands[NL80211_BAND_5GHZ] = &band_5ghz;
	wiphy->bands[NL80211_BAND_60GHZ] = NULL;
	wiphy->bands[NL80211_BAND_6GHZ] = &band_6ghz;

	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);

	/* Set security capabilities */
	wiphy->akm_suites = akm_suites;
	wiphy->n_akm_suites = ARRAY_SIZE(akm_suites);
	wiphy->cipher_suites = cipher_suites;
	wiphy->n_cipher_suites = ARRAY_SIZE(cipher_suites);

	/* Offload handshakes (the host take care of it) */
	wiphy_ext_feature_set(wiphy,
			      NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK);

	w_priv = wiphy_priv(wiphy);
	w_priv->being_deleted = false;
	w_priv->scan_request = NULL;
	INIT_WORK(&w_priv->scan_result, proxy_wifi_scan_result);
	INIT_DELAYED_WORK(&w_priv->scan_timeout, proxy_wifi_scan_timeout);
	INIT_WORK(&w_priv->handle_notif, proxy_wifi_handle_notifications);
	INIT_LIST_HEAD(&w_priv->pending_notifs);
	w_priv->notif_thread = NULL;
	w_priv->notification_socket = NULL;
	w_priv->request_port = PROXY_WIFI_REQUEST_PORT;
	w_priv->notification_port = PROXY_WIFI_NOTIFICATION_PORT;

	/* Initialize the driver workqueue */
	w_priv->workqueue = create_singlethread_workqueue("proxy_wifi");
	if (!w_priv->workqueue) {
		wiphy_err(wiphy, "Failed creating a work queue\n");
		err = -EINVAL;
		goto delete_wiphy;
	}

	err = wiphy_register(wiphy);
	if (err < 0)
		goto delete_workqueue;

	return wiphy;

delete_workqueue:
	destroy_workqueue(w_priv->workqueue);
delete_wiphy:
	wiphy_free(wiphy);
	return NULL;
}

/* Acquires and releases the rtnl lock. */
static void proxy_wifi_destroy_wiphy(struct wiphy *wiphy)
{
	struct proxy_wifi_wiphy_priv *w_priv;

	WARN(!wiphy, "proxy_wifi: %s called with null wiphy", __func__);
	if (!wiphy)
		return;

	w_priv = wiphy_priv(wiphy);

	write_lock(&proxy_wifi_context_lock);
	w_priv->being_deleted = true;
	write_unlock(&proxy_wifi_context_lock);

	proxy_wifi_cancel_scan(wiphy);

	/* Empty the workqueue */
	destroy_workqueue(w_priv->workqueue);

	if (wiphy->registered)
		wiphy_unregister(wiphy);
	wiphy_free(wiphy);
}

/* Enters and exits a RCU-bh critical section. */
/* Aquires and releases proxy_wifi_context_lock. */
static netdev_tx_t proxy_wifi_start_xmit(struct sk_buff *skb,
					 struct net_device *dev)
{
	bool is_connected = false;
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(dev);

	read_lock(&proxy_wifi_context_lock);
	is_connected = n_priv->connection.is_connected;
	read_unlock(&proxy_wifi_context_lock);

	n_priv->connection.tx_packets++;
	if (!is_connected)
		n_priv->connection.tx_failed++;

	if (!is_connected)
		return NET_XMIT_DROP;

	skb->dev = n_priv->lowerdev;
	return dev_queue_xmit(skb);
}

/* Called with rtnl lock held. */
static int proxy_wifi_net_device_open(struct net_device *dev)
{
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(dev);

	netdev_info(dev, "proxy_wifi: underlying device up");
	write_lock(&proxy_wifi_context_lock);
	n_priv->is_up = true;
	write_unlock(&proxy_wifi_context_lock);
	return 0;
}

/* Called with rtnl lock held. */
static int proxy_wifi_net_device_stop(struct net_device *dev)
{
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(dev);

	netdev_info(dev, "proxy_wifi: underlying device down\n");

	write_lock(&proxy_wifi_context_lock);
	n_priv->is_up = false;
	write_unlock(&proxy_wifi_context_lock);

	if (!dev->ieee80211_ptr)
		return 0;

	netif_carrier_off(dev);
	proxy_wifi_cancel_scan(dev->ieee80211_ptr->wiphy);
	proxy_wifi_cancel_connect(dev);

	return 0;
}

static int proxy_wifi_net_device_get_iflink(const struct net_device *dev)
{
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(dev);

	return n_priv->lowerdev->ifindex;
}

static const struct net_device_ops proxy_wifi_ops = {
	.ndo_start_xmit = proxy_wifi_start_xmit,
	.ndo_open = proxy_wifi_net_device_open,
	.ndo_stop = proxy_wifi_net_device_stop,
	.ndo_get_iflink = proxy_wifi_net_device_get_iflink,
};

/* Invoked as part of rtnl lock release. */
static void proxy_wifi_net_device_destructor(struct net_device *dev)
{
	/* Delayed past dellink to allow nl80211 to react to the device being
	 * deleted.
	 */
	kfree(dev->ieee80211_ptr);
	dev->ieee80211_ptr = NULL;
}

/* No lock interaction. */
static void proxy_wifi_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->netdev_ops = &proxy_wifi_ops;
	dev->needs_free_netdev = true;
}

/* Called in a RCU read critical section from netif_receive_skb. */
/* Aquires and releases proxy_wifi_context_lock. */
static rx_handler_result_t proxy_wifi_rx_handler(struct sk_buff **pskb)
{
	bool is_connected = false;
	struct sk_buff *skb = *pskb;
	struct proxy_wifi_netdev_priv *n_priv =
		rcu_dereference(skb->dev->rx_handler_data);

	read_lock(&proxy_wifi_context_lock);
	is_connected = n_priv->connection.is_connected;
	read_unlock(&proxy_wifi_context_lock);

	if (!is_connected)
		return RX_HANDLER_PASS;

	/* GFP_ATOMIC because this is a packet interrupt handler. */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		dev_err(&n_priv->upperdev->dev,
			"proxy_wifi: Can't skb_share_check\n");
		return RX_HANDLER_CONSUMED;
	}

	*pskb = skb;
	skb->dev = n_priv->upperdev;
	skb->pkt_type = PACKET_HOST;
	return RX_HANDLER_ANOTHER;
}

/* Called with rtnl lock held. */
static int proxy_wifi_newlink(struct net *src_net, struct net_device *dev,
			      struct nlattr *tb[], struct nlattr *data[],
			      struct netlink_ext_ack *extack)
{
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(dev);
	struct proxy_wifi_wiphy_priv *w_priv = wiphy_priv(common_wiphy);
	int err = 0;
	bool netdev_already_present = false;

	netdev_info(dev, "proxy_wifi: New link\n");

	/* Only one netdev is supported by the driver */
	read_lock(&proxy_wifi_context_lock);
	netdev_already_present = !!w_priv->netdev;
	read_unlock(&proxy_wifi_context_lock);

	if (netdev_already_present)
		return -EALREADY;

	if (!tb[IFLA_LINK])
		return -EINVAL;

	/* Start listening for notifications if not already done */
	if (!w_priv->notification_socket) {
		err = setup_notification_channel(w_priv);
		if (err) {
			netdev_err(dev,
				   "proxy_wifi: can't start the notification channel: %d\n",
				   err);
			return err;
		}
	}

	netif_carrier_off(dev);

	n_priv->upperdev = dev;
	n_priv->lowerdev =
		__dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));

	if (!n_priv->lowerdev)
		return -ENODEV;
	if (!tb[IFLA_MTU])
		dev->mtu = n_priv->lowerdev->mtu;
	else if (dev->mtu > n_priv->lowerdev->mtu)
		return -EINVAL;

	err = netdev_rx_handler_register(n_priv->lowerdev, proxy_wifi_rx_handler,
					 n_priv);
	if (err) {
		dev_err(&n_priv->lowerdev->dev,
			"proxy_wifi: Can't netdev_rx_handler_register: %d\n",
			err);
		return err;
	}

	eth_hw_addr_inherit(dev, n_priv->lowerdev);
	netif_stacked_transfer_operstate(n_priv->lowerdev, dev);

	SET_NETDEV_DEV(dev, &n_priv->lowerdev->dev);
	dev->ieee80211_ptr = kzalloc(sizeof(*dev->ieee80211_ptr), GFP_KERNEL);

	if (!dev->ieee80211_ptr) {
		err = -ENOMEM;
		goto remove_handler;
	}

	dev->ieee80211_ptr->iftype = NL80211_IFTYPE_STATION;
	dev->ieee80211_ptr->wiphy = common_wiphy;

	err = register_netdevice(dev);
	if (err) {
		dev_err(&n_priv->lowerdev->dev,
			"proxy_wifi: can't register_netdevice: %d\n", err);
		goto free_wireless_dev;
	}

	err = netdev_upper_dev_link(n_priv->lowerdev, dev, extack);
	if (err) {
		dev_err(&n_priv->lowerdev->dev,
			"proxy_wifi: can't netdev_upper_dev_link: %d\n", err);
		goto unregister_netdev;
	}

	dev->priv_destructor = proxy_wifi_net_device_destructor;
	n_priv->being_deleted = false;
	n_priv->is_up = false;
	n_priv->connect_req_ctx = NULL;
	INIT_WORK(&n_priv->connect, proxy_wifi_connect_complete);
	INIT_WORK(&n_priv->disconnect, proxy_wifi_disconnect_complete);

	write_lock(&proxy_wifi_context_lock);
	n_priv->connection.is_connected = false;
	eth_zero_addr(n_priv->connection.bssid);
	n_priv->connection.signal = 0;
	n_priv->connection.tx_packets = 0;
	n_priv->connection.tx_failed = 0;

	w_priv->netdev = dev;
	write_unlock(&proxy_wifi_context_lock);

	__module_get(THIS_MODULE);

	return 0;

unregister_netdev:
	unregister_netdevice(dev);
free_wireless_dev:
	kfree(dev->ieee80211_ptr);
	dev->ieee80211_ptr = NULL;
remove_handler:
	netdev_rx_handler_unregister(n_priv->lowerdev);

	return err;
}

/* Called with rtnl lock held. */
static void proxy_wifi_dellink(struct net_device *dev, struct list_head *head)
{
	struct proxy_wifi_netdev_priv *n_priv = netdev_priv(dev);
	struct proxy_wifi_wiphy_priv *w_priv = wiphy_priv(common_wiphy);

	netdev_info(dev, "proxy_wifi: Delete link\n");

	/* Reject incoming notifications and cfg80211 requests */
	write_lock(&proxy_wifi_context_lock);
	n_priv->being_deleted = true;
	w_priv->netdev = NULL;
	write_unlock(&proxy_wifi_context_lock);

	if (dev->ieee80211_ptr)
		proxy_wifi_cancel_scan(dev->ieee80211_ptr->wiphy);

	proxy_wifi_cancel_connect(dev);
	flush_workqueue(w_priv->workqueue);

	/* Stop accepting notification from the host */
	stop_notification_channel(w_priv);

	/* At this point, no request or notif needs the netdev anymore */

	kfree(n_priv->connect_req_ctx);
	n_priv->connect_req_ctx = NULL;

	netif_carrier_off(dev);

	netdev_rx_handler_unregister(n_priv->lowerdev);
	netdev_upper_dev_unlink(n_priv->lowerdev, dev);

	unregister_netdevice_queue(dev, head);

	module_put(THIS_MODULE);

	/* Deleting the wiphy is handled in the module destructor. */
}

static struct rtnl_link_ops proxy_wifi_link_ops = {
	.kind = "proxy_wifi",
	.setup = proxy_wifi_setup,
	.newlink = proxy_wifi_newlink,
	.dellink = proxy_wifi_dellink,
	.priv_size = sizeof(struct proxy_wifi_netdev_priv),
};

static bool netif_is_proxy_wifi_dev(const struct net_device *dev)
{
	return rcu_access_pointer(dev->rx_handler) == proxy_wifi_rx_handler;
}

static int proxy_wifi_event(struct notifier_block *this, unsigned long event,
			    void *ptr)
{
	struct net_device *lower_dev = netdev_notifier_info_to_dev(ptr);
	struct proxy_wifi_netdev_priv *n_priv;
	struct net_device *upper_dev;
	LIST_HEAD(list_kill);

	if (!netif_is_proxy_wifi_dev(lower_dev))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UNREGISTER:
		n_priv = rtnl_dereference(lower_dev->rx_handler_data);
		if (!n_priv)
			return NOTIFY_DONE;

		upper_dev = n_priv->upperdev;

		upper_dev->rtnl_link_ops->dellink(upper_dev, &list_kill);
		unregister_netdevice_many(&list_kill);
		break;
	case NETDEV_CHANGEADDR:
		n_priv = rtnl_dereference(lower_dev->rx_handler_data);
		if (!n_priv)
			return NOTIFY_DONE;

		upper_dev = n_priv->upperdev;
		eth_hw_addr_inherit(upper_dev, lower_dev);
		netif_stacked_transfer_operstate(lower_dev, upper_dev);

		netdev_info(upper_dev, "proxy_wifi: MAC address update\n");
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block proxy_wifi_notifier = {
	.notifier_call = proxy_wifi_event,
};

/* Acquires and releases the rtnl lock. */
static int __init proxy_wifi_init_module(void)
{
	int err;

	err = register_netdevice_notifier(&proxy_wifi_notifier);
	if (err)
		return err;

	err = -ENOMEM;
	common_wiphy = proxy_wifi_make_wiphy();
	if (!common_wiphy)
		goto notifier;

	err = rtnl_link_register(&proxy_wifi_link_ops);
	if (err)
		goto destroy_wiphy;

	return 0;

destroy_wiphy:
	proxy_wifi_destroy_wiphy(common_wiphy);
notifier:
	unregister_netdevice_notifier(&proxy_wifi_notifier);
	return err;
}

/* Acquires and releases the rtnl lock. */
static void __exit proxy_wifi_cleanup_module(void)
{
	/* Will delete any devices that depend on the wiphy. */
	rtnl_link_unregister(&proxy_wifi_link_ops);
	proxy_wifi_destroy_wiphy(common_wiphy);
	unregister_netdevice_notifier(&proxy_wifi_notifier);
}

module_init(proxy_wifi_init_module);
module_exit(proxy_wifi_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Guillaume Hetier <guhetier@microsoft.com>");
MODULE_DESCRIPTION("Driver for a wireless wrapper of ethernet devices");
MODULE_ALIAS_RTNL_LINK("proxy_wifi");
