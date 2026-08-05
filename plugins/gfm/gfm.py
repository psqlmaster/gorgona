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
# [ СЕКЦИЯ ГЛОБАЛЬНОЙ КОНФИГУРАЦИИ ]
# ==============================================================================

# Хэш канала управления (ваш публичный ключ)
MY_PUB_HASH = "+I9IQuXYW8I=" 

# Имя текущего узла (hostname)
NODE_NAME = os.uname()[1]

# Параметры HA (в секундах)
HEARTBEAT_INTERVAL = 20   # Как часто Лидер шлет пульс (LEADER_STATUS)
ELECTION_TIMEOUT = 70     # Сколько Реплика ждет пульса перед началом выборов
MONITOR_INTERVAL = 180    # Как часто слать отчет мониторинга (MONITOR) в канал
DEFAULT_TTL = 86400       # Время жизни алертов в базе gorgonad (1 день)

# Параметры кластера
QUORUM_TOTAL_NODES = 3    

# Системные пути к бинарникам
GORGONA_BIN = "/usr/bin/gorgona"
PSQL_BIN = "/usr/bin/psql"
PG_CTL_BIN = "/usr/bin/pg_ctlcluster" 

# Пути к файлам конфигурации и ключам
PUB_KEY_PATH = "/etc/gorgona/" + MY_PUB_HASH + ".pub"
PRIV_KEY_PATH = "/etc/gorgona/" + MY_PUB_HASH + ".key"
PUB_KEY_ARG = MY_PUB_HASH + ".pub" 
GORGONAD_CONF = "/etc/gorgona/gorgonad.conf"
STATUS_JSON = "/etc/gorgona/cluster_status.json"
REBUILD_SCRIPT = "/usr/local/bin/gfm_rebuild.sh"

# ==============================================================================
# [ КЛАСС GFM (Gorgona Failover Manager) ]
# ==============================================================================

class GFM:
    def __init__(self):
        # --- Внутреннее состояние ---
        self.role = "STANDBY"
        self.leader_name = None
        self.last_leader_heartbeat = time.time()
        self.last_monitor_sent = 0
        self.current_lsn = "0/0"
        self.is_running = True
        
        # --- Блокировки и флаги ---
        # Используем RLock (рекурсивный), чтобы поток мог повторно входить в замок
        self.lock = threading.RLock() 
        self.rebuild_in_progress = False
        
        # --- Инициализация окружения ---
        self.fix_etc_hosts()
        self.is_witness = self.detect_witness_mode()
        self.psk = self.load_psk_from_config()
        
        # --- Определение роли на основе состояния БД ---
        if self.is_witness == True:
            self.role = "WITNESS"
        else:
            try:
                self.sync_role_with_db()
            except Exception as e:
                self.log("Initial DB sync failed: " + str(e))
            
        self.log("--- GFM INITIALIZED --- Node: " + str(NODE_NAME) + " | Role: " + str(self.role))

        # --- Прогрев (чтение истории меша перед стартом) ---
        try:
            self.warmup_mesh_state()
        except Exception as e:
            self.log("Warmup notice: " + str(e))

    # --------------------------------------------------------------------------
    # ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    # --------------------------------------------------------------------------

    def log(self, msg):
        """Логирование в stdout с меткой времени и текущей ролю"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print("[" + timestamp + "] [" + self.role + "] " + str(msg), flush=True)

    def fix_etc_hosts(self):
        """Оптимизация резолвинга hostname для ускорения sudo команд"""
        try:
            with open("/etc/hosts", "r") as f:
                content = f.read()
            if NODE_NAME not in content:
                with open("/etc/hosts", "a") as f:
                    f.write("\n127.0.0.1 " + NODE_NAME + "\n")
        except:
            pass

    def detect_witness_mode(self):
        """Определяет, является ли узел Witness-нодой (без Postgres)"""
        if os.path.exists(PSQL_BIN) == False:
            return True
        try:
            import pwd
            pwd.getpwnam('postgres')
            return False
        except KeyError:
            return True

    def load_psk_from_config(self):
        """Загрузка PSK из конфигурации сервера для статус-запросов"""
        try:
            config = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
            config.read(GORGONAD_CONF)
            for section in config.sections():
                if 'sync_psk' in config[section]:
                    return config[section]['sync_psk'].strip()
        except:
            pass
        return None

    # --------------------------------------------------------------------------
    # МЕТОДЫ РАБОТЫ С POSTGRESQL
    # --------------------------------------------------------------------------

    def sync_role_with_db(self):
        """Сверяет внутреннюю роль с реальным состоянием PostgreSQL"""
        if self.is_witness == True or self.rebuild_in_progress == True:
            return
        try:
            # Проверка режима Recovery через SQL
            cmd = ["sudo", "-u", "postgres", PSQL_BIN, "-At", "-c", "SELECT pg_is_in_recovery();"]
            res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            
            if res == "f": # f = False -> База в режиме Master
                if self.role != "LEADER":
                    self.log("DB is in Master mode. Role promoted to LEADER.")
                self.role = "LEADER"
            else: # t = True -> База в режиме Standby
                if self.role == "LEADER":
                    self.log("DB is in Recovery mode. Role demoted to STANDBY.")
                self.role = "STANDBY"
        except Exception:
            # Если база данных выключена
            if self.role == "LEADER":
                self.log("DB is UNREACHABLE. Dropping LEADER status to prevent split-brain.")
            self.role = "STANDBY"

    def is_replication_active(self):
        """Проверяет, запущен ли процесс приема WAL (wal_receiver)"""
        if self.is_witness == True or self.role != "STANDBY":
            return True
        try:
            cmd = ["sudo", "-u", "postgres", PSQL_BIN, "-At", "-c", "SELECT count(*) FROM pg_stat_wal_receiver;"]
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
            res = subprocess.check_output(["sudo", "-u", "postgres", PSQL_BIN, "-At", "-c", query], stderr=subprocess.DEVNULL).decode().strip()
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
        """Действие: превращение Standby в Master"""
        if self.is_witness: return
        self.log("!!! EMERGENCY ACTION: PROMOTING TO MASTER !!!")
        cmd = ["sudo", "-u", "postgres", PG_CTL_BIN, "17", "main", "promote"]
        subprocess.run(cmd, stderr=subprocess.DEVNULL)
        self.role = "LEADER"

    # --------------------------------------------------------------------------
    # МЕТОДЫ РАБОТЫ С МЕШЕМ GORGONA
    # --------------------------------------------------------------------------

    def gorgona_send(self, message_text, ttl_sec=DEFAULT_TTL):
        """Отправка сообщения через бинарник gorgona с абсолютным временем UTC"""
        now_utc = datetime.now(timezone.utc)
        start_str = now_utc.strftime('%Y-%m-%d %H:%M:%S')
        expire_str = (now_utc + timedelta(seconds=ttl_sec)).strftime('%Y-%m-%d %H:%M:%S')
        
        cmd = [GORGONA_BIN, "send", start_str, expire_str, message_text, PUB_KEY_ARG]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

    def broadcast_status(self):
        """Пульс Лидера (LEADER_STATUS)"""
        if self.role != "LEADER": return
        current_lsn_now = self.get_pg_lsn()
        # Хертбит живет 30 секунд в меше
        self.gorgona_send("LEADER_STATUS|" + NODE_NAME + "|" + current_lsn_now, ttl_sec=DEFAULT_TTL)

    def warmup_mesh_state(self):
        """Разогрев состояния из истории меша перед началом цикла"""
        cmd = [GORGONA_BIN, "listen", "last", "5", MY_PUB_HASH]
        try:
            res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10).decode()
            for line in res.splitlines():
                if "|" in line:
                    self.process_message(line.strip())
        except:
            pass

    def auto_rebuild(self, target_master_host, reason_description):
        """Процедура автоматического запуска ребилда базы в фоне"""
        with self.lock:
            if self.is_witness == True:
                return
            if self.rebuild_in_progress == True:
                return
            self.rebuild_in_progress = True
        
        self.log("!!! INITIATING AUTO-REBUILD !!! Master: " + str(target_master_host) + " | Reason: " + reason_description)
        
        def run_recovery_process():
            try:
                if os.path.exists(REBUILD_SCRIPT):
                    # Передаем имя мастера аргументом $1 в bash-скрипт
                    subprocess.run(
                        ["/bin/bash", REBUILD_SCRIPT, str(target_master_host)],
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL
                    )
            except Exception as e:
                self.log("Background recovery thread error: " + str(e))
            finally:
                self.log("Background recovery thread finished.")
                with self.lock:
                    self.rebuild_in_progress = False
                # Пауза для инициализации Postgres
                time.sleep(5)
                self.sync_role_with_db()

        # Запускаем поток
        recovery_thread = threading.Thread(target=run_recovery_process, daemon=True)
        recovery_thread.start()
        self.role = "STANDBY"

    # --------------------------------------------------------------------------
    # ОБРАБОТКА СЕТЕВЫХ СОБЫТИЙ (LISTENER)
    # --------------------------------------------------------------------------

    def listener_thread(self):
        """Поток-слушатель меша: исправлено чтение Pipe и многострочного вывода"""
        self.log("Mesh Listener Thread active on " + MY_PUB_HASH)
        # stdbuf -oL отключает буферизацию вывода бинарника
        cmd = ["stdbuf", "-oL", GORGONA_BIN, "listen", "new", MY_PUB_HASH]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            
            # Флаг состояния: ждем ли мы данные на следующей строке
            is_content_on_next_line = False
            
            for line in proc.stdout:
                if self.is_running == False: 
                    break
                
                raw_line = line.strip()
                if not raw_line: 
                    continue
                
                # Сценарий А: Данные и маркер в одной строке
                if "|" in raw_line and ("LEADER_STATUS|" in raw_line or "CANDIDATE|" in raw_line):
                    self.process_message(raw_line)
                    is_content_on_next_line = False
                
                # Сценарий Б: Нашли маркер "Decrypted Content:", данные будут в следующей итерации
                elif "Decrypted Content:" in raw_line:
                    is_content_on_next_line = True
                    continue
                
                # Сценарий В: Предыдущая строка была маркером, значит текущая - наши данные
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
        if s_name == NODE_NAME: 
            return

        with self.lock:
            if msg_type == "LEADER_STATUS":
                # ОБНОВЛЯЕМ ТАЙМЕР: Мы слышим Лидера
                self.last_leader_heartbeat = time.time()
                self.leader_name = s_name
                
                # Если мы сами пытались стать лидером - отменяем
                if self.role == "CANDIDATE":
                    self.log("Leader pulse heard from " + s_name + ". Election aborted.")
                    self.role = "STANDBY"
                
                # Получаем наши текущие данные
                local_lsn_str = self.get_pg_lsn()
                my_lsn_val = self.lsn_to_int(local_lsn_str)
                rem_lsn_val = self.lsn_to_int(s_lsn)

                if self.role == "LEADER":
                    # КОНФЛИКТ: Обнаружено два мастера (Split-Brain)
                    # 1. Сначала по LSN
                    if rem_lsn_val > my_lsn_val:
                        self.auto_rebuild(s_name, "Superior LSN found: " + s_lsn)
                    # 2. По имени хоста (Tie-break), если LSN одинаков
                    elif rem_lsn_val == my_lsn_val:
                        if s_name < NODE_NAME: # Например, gorgonad1 < gorgonad2
                            self.auto_rebuild(s_name, "Tie-break priority given to " + s_name)
                        else:
                            self.log("Conflict with " + s_name + ". I have name priority. Ignoring.")
                
                elif self.role == "STANDBY":
                    # Самолечение для Standby
                    if not self.rebuild_in_progress and not self.is_witness:
                        # Случай 1: База абсолютно пустая
                        if my_lsn_val == 0:
                            self.auto_rebuild(s_name, "Initializing empty database from mesh")
                        # Случай 2: База не пустая, но wal_receiver мертв
                        elif self.is_replication_active() == False:
                            # Проверяем, не слишком ли давно был хертбит, чтобы не дергать зря
                            if (time.time() - self.last_leader_heartbeat) < 30:
                                self.auto_rebuild(s_name, "Replication link broken")

            elif msg_type == "CANDIDATE":
                # Если кто-то другой хочет власти - сравниваем силы
                if self.role in ["LEADER", "CANDIDATE"]:
                    my_lsn_val = self.lsn_to_int(self.get_pg_lsn())
                    rem_lsn_val = self.lsn_to_int(s_lsn)
                    
                    if rem_lsn_val > my_lsn_val or (rem_lsn_val == my_lsn_val and s_name < NODE_NAME):
                        self.log("Yielding candidacy to superior node: " + s_name)
                        self.role = "STANDBY"
                        self.last_leader_heartbeat = time.time()

    # --------------------------------------------------------------------------
    # ГЛАВНЫЙ ЦИКЛ УПРАВЛЕНИЯ
    # --------------------------------------------------------------------------

    def manager_loop(self):
        """ГлавныйHA-цикл (обход дерева состояний раз в 5 секунд)"""
        last_heartbeat_sent_time = 0 
        
        while self.is_running:
            now = time.time()
            
            # 1. Синхронизируем роль с реальностью Postgres
            if not self.is_witness and not self.rebuild_in_progress:
                try:
                    self.sync_role_with_db()
                except: pass
            
            # 2. Обновляем текущие показатели
            self.current_lsn = self.get_pg_lsn()
            my_lsn_val = self.lsn_to_int(self.current_lsn)
            silence_time = now - self.last_leader_heartbeat

            # --- ЛОГИКА ЛИДЕРА ---
            if self.role == "LEADER":
                if (now - last_heartbeat_sent_time) > HEARTBEAT_INTERVAL:
                    self.broadcast_status()
                    last_heartbeat_sent_time = now
            
            # --- ЛОГИКА РЕПЛИКИ ---
            elif self.role == "STANDBY":
                last_heartbeat_sent_time = 0 
                
                # ПРИОРИТЕТ 1: Выборы (если лидера нет слишком долго)
                if silence_time > ELECTION_TIMEOUT:
                    if not self.is_witness and not self.rebuild_in_progress:
                        # Мы имеем право голосовать только если в базе есть хоть какие-то данные
                        if my_lsn_val > 0:
                            self.log("TIMEOUT: Leader lost (" + str(int(silence_time)) + "s). Starting election.")
                            # Сбрасываем флаг ребилда, если он завис, выборы важнее
                            self.rebuild_in_progress = False 
                            self.start_election()
                        else:
                            # Мы пустые, просто ждем
                            if int(now) % 60 == 0:
                                self.log("Standby mode: DB is empty. Waiting for a master...")

                # ПРИОРИТЕТ 2: Ребилд (если лидер есть, но связи в Postgres нет)
                elif not self.is_witness and not self.rebuild_in_progress and self.leader_name:
                    if my_lsn_val == 0 or self.is_replication_active() == False:
                        # Чинимся только если мастер слышен в последние 30 сек
                        if silence_time < 30:
                            self.log("Loop Trigger: Replication is broken. Initializing auto-rebuild from " + str(self.leader_name))
                            self.auto_rebuild(self.leader_name, "Periodic recovery check")

            # 4. Обновление локального JSON
            try:
                status_obj = {
                    "node": NODE_NAME, "role": self.role, "lsn": self.current_lsn, 
                    "leader": self.leader_name, "rebuild": self.rebuild_in_progress, "ts": time.time()
                }
                with open(STATUS_JSON, "w") as f: 
                    json.dump(status_obj, f, indent=4)
            except: pass
            
            # 5. MONITOR телеметрия
            if (now - self.last_monitor_sent) > MONITOR_INTERVAL:
                self.gorgona_send("MONITOR|" + NODE_NAME + "|" + self.role + "|" + self.current_lsn)
                self.last_monitor_sent = now
            
            # Шаг итерации
            time.sleep(5)

    def start_election(self):
        """Протокол выборов за самого себя"""
        if self.is_witness == True:
            return
        
        self.role = "CANDIDATE"
        lsn_at_start = self.get_pg_lsn()
        self.log("ELECTION: Broadcasting candidacy with LSN " + str(lsn_at_start))
        
        # Шлем заявку с коротким TTL (20 сек)
        self.gorgona_send("CANDIDATE|" + NODE_NAME + "|" + lsn_at_start, ttl_sec=DEFAULT_TTL)
        
        # Ждем 10 секунд на протесты других узлов
        time.sleep(10)
        
        # Если за 10 секунд наша роль не изменилась обратно на STANDBY через process_message
        if self.role == "CANDIDATE":
            self.promote_node()

# ==============================================================================
# [ ТОЧКА ВХОДА ]
# ==============================================================================

if __name__ == "__main__":
    # Проверка ключей
    if os.path.exists(PRIV_KEY_PATH) == False:
        print("FATAL ERROR: Control key " + PRIV_KEY_PATH + " not found!")
        sys.exit(1)

    # Создание объекта GFM
    gfm_instance = GFM()
    
    # Запуск потока прослушивания
    mesh_listener = threading.Thread(target=gfm_instance.listener_thread, daemon=True)
    mesh_listener.start()
    
    # Запуск основного цикла в главном потоке
    try:
        gfm_instance.manager_loop()
    except KeyboardInterrupt:
        gfm_instance.is_running = False
        print("\nGFM stopping gracefully...")
        sys.exit(0)
    except Exception as fatal_e:
        print("\nGFM process CRASHED: " + str(fatal_e))
        sys.exit(1)
