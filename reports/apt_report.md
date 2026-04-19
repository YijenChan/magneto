# APT Investigation Report

## Summary

- Final backbone length: 5
- Covered stages: C, C&C, IR, MP, PE
- Unresolved gaps: LM
- Needs more logs: True

## Stage-oriented Findings

### Stage C
- Supporting communities: 2
- Representative entities: proc_sys_019, proc_sys_026, proc_app_009, proc_app_039
- Representative events:
  - [15:31:08] (proc_firefox, connect, domain_cdn-imgcache.com)
  - [15:32:16] (proc_app_033, read, file_/var/log/app_048.log)
  - [15:32:54] (proc_app_041, dns_query, ip_10.0.0.35)
  - [15:33:05] (proc_app_046, append, file_/home/admin/docs/doc_024.txt)

### Stage C&C
- Supporting communities: 1
- Representative entities: proc_app_005, proc_sys_006
- Representative events:
  - [13:45:10] (proc_app_042, write, file_/home/admin/docs/doc_014.txt)
  - [13:45:16] (proc_app_036, heartbeat, domain_service10.internal)
  - [13:45:18] (proc_app_046, heartbeat, ip_10.0.0.38)
  - [13:46:39] (file_/etc/cron.d/sys-sync, spawn, proc_syncsvc)

### Stage IR
- Supporting communities: 1
- Representative entities: proc_app_054, proc_sys_009
- Representative events:
  - [20:53:40] (proc_sys_013, append, file_/var/log/app_051.log)
  - [20:53:48] (proc_app_054, spawn, proc_sys_009)
  - [20:54:12] (proc_sys_015, read, file_/home/admin/docs/doc_033.txt)
  - [20:54:20] (proc_app_015, signal, proc_app_077)

### Stage PE
- Supporting communities: 1
- Representative entities: proc_app_005, proc_sys_006
- Representative events:
  - [13:45:10] (proc_app_042, write, file_/home/admin/docs/doc_014.txt)
  - [13:45:16] (proc_app_036, heartbeat, domain_service10.internal)
  - [13:45:18] (proc_app_046, heartbeat, ip_10.0.0.38)
  - [13:46:39] (file_/etc/cron.d/sys-sync, spawn, proc_syncsvc)

### Stage MP
- Supporting communities: 1
- Representative entities: proc_app_005, proc_app_039
- Representative events:
  - [21:19:27] (proc_app_047, fork, proc_app_006)
  - [21:19:51] (proc_app_011, heartbeat, domain_service20.internal)
  - [21:20:18] (proc_app_053, stat, file_/home/admin/docs/doc_037.txt)
  - [21:20:29] (file_/var/log/app_003.log, spawn, proc_app_017)

## Backbone Communities

### PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C010
- Community ID: C010
- PG ID: PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign
- Time span: 2026-04-01 15:30:00 -> 2026-04-01 15:37:30
- Stage hints: C
- Suspicious nodes: proc_sys_019, proc_sys_026
- Anomaly density: 1.0
- Bridge intensity: 21
- Trace preview:
  - [15:31:08] (proc_firefox, connect, domain_cdn-imgcache.com)
  - [15:32:16] (proc_app_033, read, file_/var/log/app_048.log)
  - [15:32:54] (proc_app_041, dns_query, ip_10.0.0.35)
  - [15:33:05] (proc_app_046, append, file_/home/admin/docs/doc_024.txt)
  - [15:33:30] (proc_app_009, spawn, proc_app_039)
  - [15:33:59] (proc_sys_039, fork, proc_sys_015)
  - [15:34:43] (proc_app_028, open, file_/var/log/app_014.log)
  - [15:34:47] (file_/tmp/cache_020.dat, copy, file_/home/admin/docs/doc_001.txt)

### PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C003
- Community ID: C003
- PG ID: PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign
- Time span: 2026-04-01 15:30:00 -> 2026-04-01 15:37:30
- Stage hints: C
- Suspicious nodes: proc_app_009, proc_app_039
- Anomaly density: 1.0
- Bridge intensity: 19
- Trace preview:
  - [15:31:08] (proc_firefox, connect, domain_cdn-imgcache.com)
  - [15:32:16] (proc_app_033, read, file_/var/log/app_048.log)
  - [15:32:54] (proc_app_041, dns_query, ip_10.0.0.35)
  - [15:33:05] (proc_app_046, append, file_/home/admin/docs/doc_024.txt)
  - [15:33:30] (proc_app_009, spawn, proc_app_039)
  - [15:33:59] (proc_sys_039, fork, proc_sys_015)
  - [15:34:43] (proc_app_028, open, file_/var/log/app_014.log)
  - [15:34:47] (file_/tmp/cache_020.dat, copy, file_/home/admin/docs/doc_001.txt)

### PG_2026-04-01_13-45-00_2026-04-01_13-48-45_malicious::C011
- Community ID: C011
- PG ID: PG_2026-04-01_13-45-00_2026-04-01_13-48-45_malicious
- Time span: 2026-04-01 13:45:00 -> 2026-04-01 13:48:45
- Stage hints: C&C, PE
- Suspicious nodes: proc_app_005, proc_sys_006
- Anomaly density: 1.0
- Bridge intensity: 17
- Trace preview:
  - [13:45:10] (proc_app_042, write, file_/home/admin/docs/doc_014.txt)
  - [13:45:16] (proc_app_036, heartbeat, domain_service10.internal)
  - [13:45:18] (proc_app_046, heartbeat, ip_10.0.0.38)
  - [13:46:39] (file_/etc/cron.d/sys-sync, spawn, proc_syncsvc)
  - [13:47:14] (proc_app_006, write, file_/home/admin/docs/doc_039.txt)
  - [13:47:30] (proc_app_035, rotate_log, file_/var/log/app_007.log)
  - [13:47:35] (proc_app_005, signal, proc_sys_006)
  - [13:47:48] (proc_app_078, read, file_/var/log/app_032.log)

### PG_2026-04-01_20-52-30_2026-04-01_20-56-15_benign::C005
- Community ID: C005
- PG ID: PG_2026-04-01_20-52-30_2026-04-01_20-56-15_benign
- Time span: 2026-04-01 20:52:30 -> 2026-04-01 20:56:15
- Stage hints: IR
- Suspicious nodes: proc_app_054, proc_sys_009
- Anomaly density: 1.0
- Bridge intensity: 17
- Trace preview:
  - [20:53:40] (proc_sys_013, append, file_/var/log/app_051.log)
  - [20:53:48] (proc_app_054, spawn, proc_sys_009)
  - [20:54:12] (proc_sys_015, read, file_/home/admin/docs/doc_033.txt)
  - [20:54:20] (proc_app_015, signal, proc_app_077)
  - [20:55:19] (proc_sys_011, open, file_/etc/passwd)
  - [20:55:40] (proc_app_024, rotate_log, file_/home/admin/docs/doc_003.txt)
  - [20:55:52] (proc_app_057, open, file_/var/log/syslog)
  - [20:55:54] (proc_app_023, stat, file_/var/log/app_053.log)

### PG_2026-04-01_21-18-45_2026-04-01_21-22-30_malicious::C004
- Community ID: C004
- PG ID: PG_2026-04-01_21-18-45_2026-04-01_21-22-30_malicious
- Time span: 2026-04-01 21:18:45 -> 2026-04-01 21:22:30
- Stage hints: MP
- Suspicious nodes: proc_app_005, proc_app_039
- Anomaly density: 1.0
- Bridge intensity: 16
- Trace preview:
  - [21:19:27] (proc_app_047, fork, proc_app_006)
  - [21:19:51] (proc_app_011, heartbeat, domain_service20.internal)
  - [21:20:18] (proc_app_053, stat, file_/home/admin/docs/doc_037.txt)
  - [21:20:29] (file_/var/log/app_003.log, spawn, proc_app_017)
  - [21:20:30] (proc_app_032, dns_query, domain_service12.internal)
  - [21:20:49] (proc_tarmini, write, file_/tmp/.stage/archive_01.tar)
  - [21:20:55] (proc_app_005, fork, proc_app_039)
  - [21:20:58] (proc_sys_032, open, file_/var/log/app_030.log)

## Investigation Reasoning

- COI=PG_2026-04-01_12-00-00_2026-04-01_12-03-45_benign::C001 | step=1 | action=discard | selected=PG_2026-04-01_20-45-00_2026-04-01_20-48-45_benign::C005 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-00-00_2026-04-01_12-03-45_benign::C001 | step=2 | action=retain | selected=PG_2026-04-01_18-07-30_2026-04-01_18-15-00_benign::C002 | reason=Strong structural and anomaly evidence.
- COI=PG_2026-04-01_12-00-00_2026-04-01_12-03-45_benign::C001 | step=3 | action=discard | selected=PG_2026-04-01_18-52-30_2026-04-01_19-00-00_benign::C008 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-00-00_2026-04-01_12-03-45_benign::C001 | step=4 | action=discard | selected=PG_2026-04-01_21-18-45_2026-04-01_21-22-30_malicious::C004 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-00-00_2026-04-01_12-03-45_benign::C001 | step=5 | action=discard | selected=PG_2026-04-01_21-52-30_2026-04-01_22-00-00_benign::C003 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-00-00_2026-04-01_12-03-45_benign::C001 | step=6 | action=discard | selected=PG_2026-04-01_23-26-15_2026-04-01_23-30-00_benign::C004 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-00-00_2026-04-01_12-03-45_benign::C001 | step=7 | action=discard | selected=PG_2026-04-01_23-56-15_2026-04-02_00-00-00_benign::C009 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-00-00_2026-04-01_12-03-45_benign::C001 | step=8 | action=discard | selected=PG_2026-04-01_20-37-30_2026-04-01_20-45-00_benign::C000 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-41-15_2026-04-01_15-45-00_benign::C000 | step=1 | action=retain | selected=PG_2026-04-01_17-30-00_2026-04-01_17-33-45_benign::C001 | reason=Strong structural and anomaly evidence.
- COI=PG_2026-04-01_15-41-15_2026-04-01_15-45-00_benign::C000 | step=2 | action=discard | selected=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C008 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-41-15_2026-04-01_15-45-00_benign::C000 | step=3 | action=discard | selected=PG_2026-04-01_18-45-00_2026-04-01_18-48-45_benign::C005 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-41-15_2026-04-01_15-45-00_benign::C000 | step=4 | action=discard | selected=PG_2026-04-01_23-15-00_2026-04-01_23-18-45_benign::C003 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-41-15_2026-04-01_15-45-00_benign::C000 | step=5 | action=discard | selected=PG_2026-04-01_23-18-45_2026-04-01_23-22-30_benign::C003 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-41-15_2026-04-01_15-45-00_benign::C000 | step=6 | action=discard | selected=PG_2026-04-01_17-45-00_2026-04-01_17-52-30_benign::C011 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-41-15_2026-04-01_15-45-00_benign::C000 | step=7 | action=discard | selected=PG_2026-04-01_19-33-45_2026-04-01_19-37-30_benign::C001 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-41-15_2026-04-01_15-45-00_benign::C000 | step=8 | action=discard | selected=PG_2026-04-01_19-37-30_2026-04-01_19-45-00_benign::C001 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_17-30-00_2026-04-01_17-33-45_benign::C001 | step=1 | action=discard | selected=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C008 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_17-30-00_2026-04-01_17-33-45_benign::C001 | step=2 | action=discard | selected=PG_2026-04-01_18-45-00_2026-04-01_18-48-45_benign::C005 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_17-30-00_2026-04-01_17-33-45_benign::C001 | step=3 | action=discard | selected=PG_2026-04-01_23-15-00_2026-04-01_23-18-45_benign::C003 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_17-30-00_2026-04-01_17-33-45_benign::C001 | step=4 | action=discard | selected=PG_2026-04-01_23-18-45_2026-04-01_23-22-30_benign::C003 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_17-30-00_2026-04-01_17-33-45_benign::C001 | step=5 | action=discard | selected=PG_2026-04-01_17-45-00_2026-04-01_17-52-30_benign::C011 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_17-30-00_2026-04-01_17-33-45_benign::C001 | step=6 | action=discard | selected=PG_2026-04-01_19-33-45_2026-04-01_19-37-30_benign::C001 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_17-30-00_2026-04-01_17-33-45_benign::C001 | step=7 | action=discard | selected=PG_2026-04-01_19-37-30_2026-04-01_19-45-00_benign::C001 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_17-30-00_2026-04-01_17-33-45_benign::C001 | step=8 | action=discard | selected=PG_2026-04-01_20-52-30_2026-04-01_20-56-15_benign::C005 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_22-45-00_2026-04-01_22-48-45_benign::C000 | step=1 | action=discard | selected=PG_2026-04-01_23-00-00_2026-04-01_23-15-00_benign::C010 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_22-45-00_2026-04-01_22-48-45_benign::C000 | step=2 | action=terminate | selected=None | reason=No more supported candidates.
- COI=PG_2026-04-01_14-11-15_2026-04-01_14-15-00_benign::C006 | step=1 | action=discard | selected=PG_2026-04-01_18-45-00_2026-04-01_18-48-45_benign::C003 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_14-11-15_2026-04-01_14-15-00_benign::C006 | step=2 | action=discard | selected=PG_2026-04-01_22-00-00_2026-04-01_22-03-45_benign::C008 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_14-11-15_2026-04-01_14-15-00_benign::C006 | step=3 | action=discard | selected=PG_2026-04-01_22-07-30_2026-04-01_22-15-00_benign::C002 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_14-11-15_2026-04-01_14-15-00_benign::C006 | step=4 | action=discard | selected=PG_2026-04-01_23-26-15_2026-04-01_23-30-00_benign::C001 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_14-11-15_2026-04-01_14-15-00_benign::C006 | step=5 | action=discard | selected=PG_2026-04-01_15-56-15_2026-04-01_16-00-00_benign::C005 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_14-11-15_2026-04-01_14-15-00_benign::C006 | step=6 | action=discard | selected=PG_2026-04-01_16-22-30_2026-04-01_16-26-15_benign::C007 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_14-11-15_2026-04-01_14-15-00_benign::C006 | step=7 | action=discard | selected=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C004 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_14-11-15_2026-04-01_14-15-00_benign::C006 | step=8 | action=discard | selected=PG_2026-04-01_18-52-30_2026-04-01_19-00-00_benign::C011 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C010 | step=1 | action=discard | selected=PG_2026-04-01_17-30-00_2026-04-01_17-33-45_benign::C001 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C010 | step=2 | action=discard | selected=PG_2026-04-01_16-07-30_2026-04-01_16-11-15_benign::C008 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C010 | step=3 | action=discard | selected=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C008 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C010 | step=4 | action=discard | selected=PG_2026-04-01_18-45-00_2026-04-01_18-48-45_benign::C005 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C010 | step=5 | action=discard | selected=PG_2026-04-01_18-45-00_2026-04-01_18-48-45_benign::C006 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C010 | step=6 | action=discard | selected=PG_2026-04-01_21-18-45_2026-04-01_21-22-30_malicious::C010 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C010 | step=7 | action=discard | selected=PG_2026-04-01_23-15-00_2026-04-01_23-18-45_benign::C004 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C010 | step=8 | action=discard | selected=PG_2026-04-01_16-37-30_2026-04-01_16-41-15_benign::C003 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C004 | step=1 | action=discard | selected=PG_2026-04-01_18-18-45_2026-04-01_18-22-30_benign::C008 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C004 | step=2 | action=discard | selected=PG_2026-04-01_19-37-30_2026-04-01_19-45-00_benign::C006 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C004 | step=3 | action=discard | selected=PG_2026-04-01_21-52-30_2026-04-01_22-00-00_benign::C001 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C004 | step=4 | action=discard | selected=PG_2026-04-01_22-37-30_2026-04-01_22-45-00_benign::C002 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C004 | step=5 | action=discard | selected=PG_2026-04-01_23-00-00_2026-04-01_23-15-00_benign::C010 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C004 | step=6 | action=discard | selected=PG_2026-04-01_18-45-00_2026-04-01_18-48-45_benign::C003 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C004 | step=7 | action=discard | selected=PG_2026-04-01_21-18-45_2026-04-01_21-22-30_malicious::C006 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_18-15-00_2026-04-01_18-18-45_benign::C004 | step=8 | action=discard | selected=PG_2026-04-01_22-00-00_2026-04-01_22-03-45_benign::C008 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-15-00_2026-04-01_12-22-30_benign::C001 | step=1 | action=discard | selected=PG_2026-04-01_12-30-00_2026-04-01_12-37-30_benign::C009 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-15-00_2026-04-01_12-22-30_benign::C001 | step=2 | action=discard | selected=PG_2026-04-01_15-30-00_2026-04-01_15-37-30_benign::C006 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-15-00_2026-04-01_12-22-30_benign::C001 | step=3 | action=discard | selected=PG_2026-04-01_16-03-45_2026-04-01_16-07-30_benign::C003 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-15-00_2026-04-01_12-22-30_benign::C001 | step=4 | action=discard | selected=PG_2026-04-01_18-18-45_2026-04-01_18-22-30_benign::C003 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-15-00_2026-04-01_12-22-30_benign::C001 | step=5 | action=discard | selected=PG_2026-04-01_18-45-00_2026-04-01_18-48-45_benign::C001 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-15-00_2026-04-01_12-22-30_benign::C001 | step=6 | action=discard | selected=PG_2026-04-01_20-30-00_2026-04-01_20-33-45_benign::C004 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-15-00_2026-04-01_12-22-30_benign::C001 | step=7 | action=discard | selected=PG_2026-04-01_23-00-00_2026-04-01_23-15-00_benign::C004 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_12-15-00_2026-04-01_12-22-30_benign::C001 | step=8 | action=discard | selected=PG_2026-04-01_23-26-15_2026-04-01_23-30-00_benign::C009 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_17-45-00_2026-04-01_17-52-30_benign::C011 | step=1 | action=discard | selected=PG_2026-04-01_18-00-00_2026-04-01_18-03-45_benign::C008 | reason=Assistant did not provide strong enough support.
- COI=PG_2026-04-01_17-45-00_2026-04-01_17-52-30_benign::C011 | step=2 | action=discard | selected=PG_2026-04-01_20-52-30_2026-04-01_20-56-15_benign::C005 | reason=Assistant did not provide strong enough support.

## Indicators of Compromise (IOCs)

- Processes: None
- Files: None
- External endpoints: None

## Completeness Assessment

The current attack backbone is not considered complete. The investigation should request earlier audit logs and update the signal from round=2 to round=1.
