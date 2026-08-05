-- на мастере должен быть стриминг
sudo -u postgres psql -tx -c "SELECT * FROM pg_stat_replication;"
/*
pid              | 29695
usesysid         | 16387
usename          | repuser
application_name | 17/main
client_addr      | 192.168.1.170
client_hostname  | 
client_port      | 47654
backend_start    | 2026-08-05 09:27:46.267563-04
backend_xmin     | 
state            | streaming
sent_lsn         | 0/69000320
write_lsn        | 0/69000320
flush_lsn        | 0/69000320
replay_lsn       | 0/69000320
write_lag        | 
flush_lag        | 
replay_lag       | 
sync_priority    | 0
sync_state       | async
reply_time       | 2026-08-05 09:35:07.879366-04

*/
-- на мастере проверить отставание в байтах и мегабайтах
sudo -u postgres psql -tx -c "
SELECT 
    pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS replay_lag_bytes,
    pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) / 1024 / 1024 AS replay_lag_mb,
    EXTRACT(EPOCH FROM (NOW() - reply_time)) AS replay_lag_seconds
FROM pg_stat_replication;"
/*
replay_lag_bytes   | 0
replay_lag_mb      | 0.00000000000000000000
replay_lag_seconds | 8.922251
*/
-- на мастере состояние слотов репликации
sudo -u postgres psql -tx -c "
SELECT 
    slot_name,
    slot_type,
    active,
    restart_lsn,
    pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS lag_bytes,
    pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) / 1024 / 1024 AS lag_mb
FROM pg_replication_slots;"
/*
slot_name   | replica_slot_gorgonad1
slot_type   | physical
active      | t
restart_lsn | 0/69000320
lag_bytes   | 0
lag_mb      | 0.00000000000000000000
*/

-- на мастере проверить проблемные реплики (если есть)
sudo -u postgres psql -tx -c "
SELECT 
    application_name,
    client_addr,
    state,
    backend_start,
    NOW() - backend_start AS session_duration,
    EXTRACT(EPOCH FROM (NOW() - reply_time)) AS last_reply_seconds
FROM pg_stat_replication
WHERE state != 'streaming' OR EXTRACT(EPOCH FROM (NOW() - reply_time)) > 60;"


-- на реплике должна быть 
sudo -u postgres psql -tx -c "select * from pg_stat_wal_receiver;"
/*
pid                   | 32006
status                | streaming
receive_start_lsn     | 0/69000000
receive_start_tli     | 5
written_lsn           | 0/69000320
flushed_lsn           | 0/69000320
received_tli          | 5
last_msg_send_time    | 2026-08-05 09:33:47.834331-04
last_msg_receipt_time | 2026-08-05 09:33:47.846856-04
latest_end_lsn        | 0/69000320
latest_end_time       | 2026-08-05 09:32:47.814374-04
slot_name             | replica_slot_gorgonad1
sender_host           | gorgonad2
sender_port           | 5432
conninfo              | user=repuser passfile=/var/lib/postgresql/.pgpass channel_binding=prefer dbname=replication host=gorgonad2 port=5432 fallback_application_name=17/main sslmode=prefer sslnegotiation=postgres sslcompression=0 sslcertmode=allow sslsni=1 ssl_min_protocol_version=TLSv1.2 gssencmode=prefer krbsrvname=postgres gssdelegation=0 target_session_attrs=any load_balance_hosts=disable
*/

-- на реплике разница между flushed и latest_end_lsn
sudo -u postgres psql -tx -c "
SELECT 
    status,
    pg_wal_lsn_diff(latest_end_lsn, flushed_lsn) AS unflushed_bytes,
    pg_wal_lsn_diff(flushed_lsn, receive_start_lsn) AS total_received_bytes,
    NOW() - last_msg_receipt_time AS last_receipt_ago
FROM pg_stat_wal_receiver;"
/*
status               | streaming
unflushed_bytes      | 0
total_received_bytes | 800
last_receipt_ago     | 00:00:16.828925
*/
