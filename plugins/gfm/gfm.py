#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import threading
import time
import json
import os
import sys
import socket
import re
import configparser
from datetime import datetime, timedelta, timezone

# ==============================================================================
# [ КЛАСС GFM (Gorgona Failover Manager) ]
# ==============================================================================

class GFM:
    def __init__(self):
        # --- Загрузка конфигурации ---
        self.load_config() 

        # --- Внутреннее состояние ---
        self.role = "STANDBY"
        self.leader_name = None
        self.last_leader_heartbeat = time.time()
        self.last_monitor_sent = 0
        self.current_lsn = "0/0"
        self.is_running = True
        
        # --- Блокировки и флаги ---
        self.lock = threading.RLock() 
        self.rebuild_in_progress = False
        
        # --- Инициализация окружения ---
        self.fix_etc_hosts()
        self.is_witness = self.detect_witness_mode()
        self.psk = self.load_psk_from_config()
        
        # --- Определение роли на основе состояния БД ---
        if self.is_witness:
            self.role = "WITNESS"
        else:
            try:
                self.sync_role_with_db()
            except Exception as e:
                self.log("Initial DB sync failed: " + str(e))
            
        self.log("--- GFM DISTRIBUTED MANAGER LOADED ---")
        self.log("Node: " + str(self.node_name) + " | Role: " + str(self.role))
        self.log("Logic: Missed Heartbeats allowed = " + str(self.max_missing_heartbeats))
        self.log("Calculated Election Timeout = " + str(self.election_timeout) + "s")

        # --- Прогрев (чтение истории меша перед стартом) ---
        try:
            self.warmup_mesh_state()
        except Exception as e:
            self.log("Warmup notice: " + str(e))

    def load_config(self):
        """Загрузка параметров из gfm.conf с учетом новых TTL"""
        config_path = "/etc/gorgona/gfm.conf"
        if not os.path.exists(config_path):
            print("FATAL: Config file not found at " + config_path)
            sys.exit(1)

        conf = configparser.ConfigParser()
        conf.read(config_path)

        # Кластер
        self.my_pub_hash = conf.get("cluster", "my_pub_hash")
        self.node_name = os.uname()[1]
        self.quorum_total_nodes = conf.getint("cluster", "quorum_total_nodes")

        # Тайминги и TTL
        self.heartbeat_interval = conf.getint("timings", "heartbeat_interval")
        self.max_missing_heartbeats = conf.getint("timings", "max_missing_heartbeats")
        self.monitor_interval = conf.getint("timings", "monitor_interval")
        
        # Специализированные TTL
        self.heartbeat_ttl = conf.getint("timings", "heartbeat_ttl")
        self.event_ttl = conf.getint("timings", "event_ttl")
        self.default_ttl = conf.getint("timings", "default_ttl")
        
        # Расчет таймаута выборов
        self.election_timeout = (self.heartbeat_interval * self.max_missing_heartbeats) + 5

        # Пути
        base = conf.get("paths", "base_dir")
        self.gorgona_bin = conf.get("paths", "gorgona_bin")
        self.psql_bin = conf.get("paths", "psql_bin")
        self.pg_ctl_bin = conf.get("paths", "pg_ctl_bin")
        self.rebuild_script = conf.get("paths", "rebuild_script")

        # Производные пути
        self.priv_key_path = base + "/" + self.my_pub_hash + ".key"
        self.pub_key_arg = self.my_pub_hash + ".pub"
        self.gorgonad_conf_path = base + "/gorgonad.conf"
        self.status_json_path = base + "/cluster_status.json"

    # --------------------------------------------------------------------------
    # ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    # --------------------------------------------------------------------------

    def log(self, msg):
        """Логирование в stdout с меткой времени"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print("[" + timestamp + "] [" + self.role + "] " + str(msg), flush=True)

    def fix_etc_hosts(self):
        """Оптимизация резолвинга для ускорения sudo команд"""
        try:
            with open("/etc/hosts", "r") as f:
                content = f.read()
            if self.node_name not in content:
                with open("/etc/hosts", "a") as f:
                    f.write("\n127.0.0.1 " + self.node_name + "\n")
        except:
            pass

    def detect_witness_mode(self):
        """Определяет, является ли узел Witness-нодой (без Postgres)"""
        if os.path.exists(self.psql_bin) == False:
            return True
        try:
            import pwd
            pwd.getpwnam('postgres')
            return False
        except KeyError:
            return True

    def load_psk_from_config(self):
        """Загрузка PSK из конфигурации gorgonad"""
        try:
            config = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
            config.read(self.gorgonad_conf_path)
            for section in config.sections():
                if 'sync_psk' in config[section]:
                    return config[section]['sync_psk'].strip()
        except:
            pass
        return None

    # --------------------------------------------------------------------------
    # РАБОТА С POSTGRESQL
    # --------------------------------------------------------------------------

    def sync_role_with_db(self):
        """Сверяет внутреннюю роль с реальным состоянием PostgreSQL"""
        if self.is_witness == True or self.rebuild_in_progress == True:
            return
        try:
            cmd = ["sudo", "-u", "postgres", self.psql_bin, "-At", "-c", "SELECT pg_is_in_recovery();"]
            res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            
            if res == "f": # Master
                if self.role != "LEADER":
                    self.log("DB is in Master mode. Role promoted to LEADER.")
                self.role = "LEADER"
            else: # Standby
                if self.role == "LEADER":
                    self.log("DB is in Recovery mode. Role demoted to STANDBY.")
                self.role = "STANDBY"
        except Exception:
            if self.role == "LEADER":
                self.log("DB UNREACHABLE. Dropping LEADER status.")
            self.role = "STANDBY"

    def is_replication_active(self):
        """Проверяет, запущен ли процесс приема WAL (wal_receiver)"""
        if self.is_witness == True or self.role != "STANDBY":
            return True
        try:
            cmd = ["sudo", "-u", "postgres", self.psql_bin, "-At", "-c", "SELECT count(*) FROM pg_stat_wal_receiver;"]
            res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            return int(res) > 0
        except Exception:
            return False

    def get_pg_lsn(self):
        """Получает текущий LSN (позицию WAL), адаптировано для Postgres 17"""
        if self.is_witness: return "0/0"
        query = """
        SELECT CASE 
            WHEN pg_is_in_recovery() THEN GREATEST(COALESCE(pg_last_wal_receive_lsn(), '0/0'), COALESCE(pg_last_wal_replay_lsn(), '0/0'))
            ELSE pg_current_wal_lsn() 
        END;
        """
        try:
            res = subprocess.check_output(["sudo", "-u", "postgres", self.psql_bin, "-At", "-c", query], stderr=subprocess.DEVNULL).decode().strip()
            if res and "/" in res:
                return res
            return "0/0"
        except:
            return "0/0"

    def lsn_to_int(self, lsn_string):
        """Конвертирует LSN строку в число для сравнения"""
        if not lsn_string or "/" not in lsn_string:
            return 0
        try:
            parts = lsn_string.split('/')
            return (int(parts[0], 16) << 32) + int(parts[1], 16)
        except:
            return 0

    def promote_node(self):
        """Переход в MASTER с записью события"""
        if self.is_witness == True:
            return
        
        self.log("ACTION: PROMOTING TO MASTER.")
        # Выполняем системную команду
        cmd = ["sudo", "-u", "postgres", self.pg_ctl_bin, "17", "main", "promote"]
        subprocess.run(cmd, stderr=subprocess.DEVNULL)
        
        self.role = "LEADER"
        # Записываем в вечную историю меша
        self.send_event("PROMOTED TO MASTER. Cluster is now serving writes on this node.")

    def demote_node(self, reason_text):
        """Жесткий Fencing: немедленная остановка Postgres для защиты данных."""
        if self.is_witness: return
        self.log("!!! FENCING !!! Reason: " + reason_text)
        self.send_event("FENCING: Stopping Postgres. Reason: " + reason_text)
        
        # Останавливаем базу. GFM при этом остается жив и переходит в STANDBY.
        subprocess.run(["systemctl", "stop", "postgresql"], stderr=subprocess.DEVNULL)
        self.role = "STANDBY"
        self.leader_name = None

    # --------------------------------------------------------------------------
    # МЕТОДЫ РАБОТЫ С МЕШЕМ GORGONA
    # --------------------------------------------------------------------------

    def gorgona_send(self, message_text, ttl_sec=None):
        """Низкоуровневая отправка через бинарник. Использует абсолютный UTC."""
        # Если TTL не указан, берем общий из конфига
        actual_ttl = ttl_sec if ttl_sec is not None else self.default_ttl
        now = datetime.now(timezone.utc)
        start_str = now.strftime('%Y-%m-%d %H:%M:%S')
        expire_time = now + timedelta(seconds=actual_ttl)
        end_str = expire_time.strftime('%Y-%m-%d %H:%M:%S')
        cmd = [self.gorgona_bin, "send", start_str, end_str, message_text, self.pub_key_arg]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.log("Gorgona binary call failed: " + str(e))

    def send_event(self, event_description):
        """
        Отправляет важное событие (Audit Log). 
        Эти сообщения живут долго (event_ttl), чтобы их можно было прочитать спустя часы.
        """
        event_msg = "EVENT|" + self.node_name + "|" + str(event_description)
        # Шлем с длинным TTL
        self.gorgona_send(event_msg, ttl_sec=self.event_ttl)
        # дублируем в локальный системный лог
        self.log("AUDIT_EVENT: " + event_description)

    def broadcast_status(self):
        """Короткоживущий пульс Лидера (Heartbeat)"""
        if self.role != "LEADER":
            return
        
        current_lsn = self.get_pg_lsn()
        msg = "LEADER_STATUS|" + self.node_name + "|" + current_lsn
        # Используем короткий TTL из конфига (heartbeat_ttl)
        self.gorgona_send(msg, ttl_sec=self.heartbeat_ttl)

    def start_election(self):
        """Процедура выборов с регистрацией события в истории"""
        if self.is_witness == True:
            return
        
        # Логируем начало выборов в историю меша (Audit Log)
        self.send_event("TIMEOUT. Initiating leader election.")
        
        self.role = "CANDIDATE"
        lsn_at_start = self.get_pg_lsn()
        
        # Сама заявка живет недолго
        self.gorgona_send("CANDIDATE|" + self.node_name + "|" + lsn_at_start, ttl_sec=30)
        
        # Ждем оспорений
        time.sleep(10)
        
        if self.role == "CANDIDATE":
            self.promote_node()

    def warmup_mesh_state(self):
        """Разогрев состояния из истории меша перед началом цикла"""
        cmd = [self.gorgona_bin, "listen", "last", "5", self.my_pub_hash]
        try:
            res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10).decode()
            for line in res.splitlines():
                if "|" in line:
                    self.process_message(line.strip())
        except:
            pass

    def auto_rebuild(self, target_master_host, reason_description):
        """Ребилд с записью в историю"""
        with self.lock:
            if self.is_witness or self.rebuild_in_progress:
                return
            self.rebuild_in_progress = True
        
        self.send_event("STARTING AUTO-RECOVERY. Source Master: " + str(target_master_host))
        
        def run_recovery_process():
            try:
                subprocess.run(
                    ["/bin/bash", self.rebuild_script, str(target_master_host)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception as e:
                self.log("Rebuild thread error: " + str(e))
                self.send_event("RECOVERY FAILED: " + str(e))
            finally:
                self.log("Rebuild finished.")
                with self.lock:
                    self.rebuild_in_progress = False
                time.sleep(5)
                self.sync_role_with_db()
                if self.role == "STANDBY":
                    self.send_event("RECOVERY SUCCESSFUL. Node is now a healthy Standby.")

        threading.Thread(target=run_recovery_process, daemon=True).start()
        self.role = "STANDBY"

    # --------------------------------------------------------------------------
    # ОБРАБОТКА СЕТЕВЫХ СОБЫТИЙ (LISTENER)
    # --------------------------------------------------------------------------

    def listener_thread(self):
        """Поток-слушатель меша: исправлено чтение Pipe и многострочного вывода"""
        self.log("Mesh Listener Thread active on " + self.my_pub_hash)
        cmd = ["stdbuf", "-oL", self.gorgona_bin, "listen", "new", self.my_pub_hash]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            is_content_on_next_line = False
            
            for line in proc.stdout:
                if self.is_running == False: 
                    break
                
                raw_line = line.strip()
                if not raw_line: 
                    continue
                
                if "|" in raw_line and ("LEADER_STATUS|" in raw_line or "CANDIDATE|" in raw_line):
                    self.process_message(raw_line)
                    is_content_on_next_line = False
                elif "Decrypted Content:" in raw_line:
                    is_content_on_next_line = True
                    continue
                elif is_content_on_next_line == True:
                    if "|" in raw_line:
                        self.process_message(raw_line)
                    is_content_on_next_line = False
                    
        except Exception as e:
            self.log("CRITICAL: Listener Thread error: " + str(e))

    def process_message(self, raw_payload):
        """Разбор сообщения и логика разрешения конфликтов (Tie-break)"""
        # RegEx находит ТИП|ИМЯ|LSN даже среди системного мусора
        pattern = r"(LEADER_STATUS|CANDIDATE)\|([^|]+)\|([0-9a-fA-F/]+)"
        match = re.search(pattern, raw_payload)
        
        if not match: 
            return

        msg_type, s_name, s_lsn = match.groups()
        
        # Не обрабатываем эхо собственных сообщений
        if s_name == self.node_name: 
            return

        with self.lock:
            # --- СЦЕНАРИЙ 1: Получен статус действующего Лидера ---
            if msg_type == "LEADER_STATUS":
                self.last_leader_heartbeat = time.time()
                self.leader_name = s_name
                
                # Если мы сами пытались стать лидером - отменяем выборы
                if self.role == "CANDIDATE":
                    self.log("Leader pulse heard from " + s_name + ". Election aborted.")
                    self.role = "STANDBY"
                
                # Сверяем наши данные с данными из пакета
                local_lsn_str = self.get_pg_lsn()
                my_lsn_val = self.lsn_to_int(local_lsn_str)
                rem_lsn_val = self.lsn_to_int(s_lsn)

                if self.role == "LEADER":
                    # КОНФЛИКТ МАСТЕРОВ (Split-Brain)
                    if rem_lsn_val > my_lsn_val:
                        # У соседа данных больше - мы обязаны уйти
                        self.demote_node("Superior LSN found: " + s_lsn)
                        self.auto_rebuild(s_name, "Rejoining as replica (inferior LSN)")
                    
                    elif rem_lsn_val == my_lsn_val:
                        # LSN равны, решаем по алфавиту
                        if s_name < self.node_name:
                            self.demote_node("Tie-break priority given to " + s_name)
                            self.auto_rebuild(s_name, "Rejoining as replica (alphabetical priority)")
                        else:
                            self.log("Conflict with " + s_name + ". I have name priority. Staying Master.")
                
                elif self.role == "STANDBY":
                    # SELF-HEALING (Авто-восстановление реплики)
                    if not self.rebuild_in_progress and not self.is_witness:
                        # Если база пуста или репликация "отсохла"
                        if my_lsn_val == 0:
                            self.log("DB is empty. Auto-initializing recovery from " + s_name)
                            self.auto_rebuild(s_name, "Initial synchronization")
                        elif self.is_replication_active() == False:
                            # Проверяем, что мастер слышен стабильно (не разовый пакет)
                            if (time.time() - self.last_leader_heartbeat) < 30:
                                self.log("Replication broken but Leader is active. Triggering rebuild.")
                                self.auto_rebuild(s_name, "Broken replication link recovery")

            # --- СЦЕНАРИЙ 2: Получена заявка от Кандидата ---
            elif msg_type == "CANDIDATE":
                if self.role in ["LEADER", "CANDIDATE"]:
                    my_lsn_val = self.lsn_to_int(self.get_pg_lsn())
                    rem_lsn_val = self.lsn_to_int(s_lsn)
                    
                    # Если кто-то другой претендует на лидерство и он сильнее нас
                    if rem_lsn_val > my_lsn_val or (rem_lsn_val == my_lsn_val and s_name < self.node_name):
                        self.log("Yielding to superior candidate: " + s_name)
                        self.role = "STANDBY"
                        # Сбрасываем таймер, чтобы не начать свои выборы сразу же
                        self.last_leader_heartbeat = time.time()

    # --------------------------------------------------------------------------
    # ГЛАВНЫЙ ЦИКЛ УПРАВЛЕНИЯ
    # --------------------------------------------------------------------------

    def manager_loop(self):
        """Главный HA-цикл"""
        last_heartbeat_sent_time = 0 
        
        while self.is_running:
            now = time.time()
            if not self.is_witness and not self.rebuild_in_progress:
                try:
                    self.sync_role_with_db()
                except: pass
            
            self.current_lsn = self.get_pg_lsn()
            my_lsn_val = self.lsn_to_int(self.current_lsn)
            silence_time = now - self.last_leader_heartbeat

            if self.role == "LEADER":
                if (now - last_heartbeat_sent_time) > self.heartbeat_interval:
                    self.broadcast_status()
                    last_heartbeat_sent_time = now
            
            elif self.role == "STANDBY":
                last_heartbeat_sent_time = 0 
                if silence_time > self.election_timeout:
                    if not self.is_witness and not self.rebuild_in_progress:
                        if my_lsn_val > 0:
                            self.log("TIMEOUT: Leader lost (" + str(int(silence_time)) + "s). Starting election.")
                            self.rebuild_in_progress = False 
                            self.start_election()
                        else:
                            if int(now) % 60 == 0:
                                self.log("Standby mode: DB is empty. Waiting for a master...")

                elif not self.is_witness and not self.rebuild_in_progress and self.leader_name:
                    if my_lsn_val == 0 or self.is_replication_active() == False:
                        if silence_time < 30:
                            self.log("Loop Trigger: Replication is broken. Initializing auto-rebuild from " + str(self.leader_name))
                            self.auto_rebuild(self.leader_name, "Periodic recovery check")

            try:
                status_obj = {
                    "node": self.node_name, "role": self.role, "lsn": self.current_lsn, 
                    "leader": self.leader_name, "rebuild": self.rebuild_in_progress, "ts": time.time()
                }
                with open(self.status_json_path, "w") as f: 
                    json.dump(status_obj, f, indent=4)
            except: pass
            
            if (now - self.last_monitor_sent) > self.monitor_interval:
                self.gorgona_send("MONITOR|" + self.node_name + "|" + self.role + "|" + self.current_lsn)
                self.last_monitor_sent = now
            
            time.sleep(5)

if __name__ == "__main__":
    # Создание объекта GFM (сначала загружаем конфиг и пути)
    gfm_instance = GFM()
    
    # Теперь проверка ключа безопасна
    if not os.path.exists(gfm_instance.priv_key_path):
        print("FATAL: Key " + gfm_instance.priv_key_path + " not found!")
        sys.exit(1)

    # Запуск потока прослушивания
    mesh_listener = threading.Thread(target=gfm_instance.listener_thread, daemon=True)
    mesh_listener.start()
    
    # Запуск основного цикла
    try:
        gfm_instance.manager_loop()
    except KeyboardInterrupt:
        gfm_instance.is_running = False
        print("\nGFM stopping gracefully...")
        sys.exit(0)
    except Exception as fatal_e:
        print("\nGFM process CRASHED: " + str(fatal_e))
        sys.exit(1)

