#!/usr/bin/env python3
"""Reproduce the QUIC/TCP lab in disposable, private network namespaces."""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess as sp
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
CURL = ROOT / "tools/curl-h3/bin/curl"
CADDY = ROOT / "tools/caddy-week6/caddy"
GTLS = ROOT / "tools/ngtcp2-week8/bin/gtlsclient"
MODES = ("baseline", "loss", "sweep", "migration", "all")


def run(argv, **kwargs):
    return sp.run([str(x) for x in argv], check=True, text=True,
                  stdout=sp.PIPE, stderr=sp.PIPE, timeout=60, **kwargs).stdout


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def number(value):
    try:
        value = float(value)
        if not math.isfinite(value) or value < 0:
            raise ValueError()
        return value
    except ValueError:
        raise argparse.ArgumentTypeError("Cần số hữu hạn không âm")


def positive(value):
    result = number(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("Cần số lớn hơn 0")
    return result


def delay(value):
    if not re.fullmatch(r"(?:\d+(?:\.\d+)?|\.\d+)(?:us|ms|s)", value):
        raise argparse.ArgumentTypeError("Ví dụ: 0ms, 20ms, 0.1s")
    return value


def rate(value):
    if value != "unlimited" and not re.fullmatch(r"(?:\d+(?:\.\d+)?|\.\d+)(?:kbit|mbit|gbit)", value):
        raise argparse.ArgumentTypeError("Ví dụ: 100mbit hoặc unlimited")
    if value != "unlimited" and float(re.match(r"[\d.]+", value)[0]) <= 0:
        raise argparse.ArgumentTypeError("Băng thông phải lớn hơn 0")
    return value


def arguments():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--mode", choices=MODES, default="loss",
                   help="baseline: tuần 3 (lưu pcap để phân tích tuần 4 bằng Wireshark); loss: tuần 5; sweep: tuần 7; migration: tuần 6; all: cả 4 bài")
    p.add_argument("--loss", type=number, default=0.5, help="Mất gói ngẫu nhiên mỗi chiều (%%)")
    p.add_argument("--delay", type=delay, default="20ms", help="Trễ thêm mỗi chiều")
    p.add_argument("--rate", type=rate, default="100mbit", help="Giới hạn mỗi chiều")
    p.add_argument("--loss-list", default="0,0.5,1,2,3,4,5,6,7,8,9,10", help="Dải mất gói của sweep/all")
    p.add_argument("--runs", type=int, default=30, help="Lượt/giao thức/điều kiện; migration chạy một cặp")
    p.add_argument("--warmups", type=int, default=0, help="Lượt khởi động/giao thức/điều kiện, lưu riêng")
    p.add_argument("--timeout", type=positive, default=120, help="Giới hạn giây mỗi lượt tải")
    p.add_argument("--pcap", choices=("first", "all"), default="first", help="Bắt gói lượt đầu hoặc mọi lượt")
    p.add_argument("--switch-after", type=positive, default=8, help="Migration: đổi route sau số giây này")
    p.add_argument("--migration-after", type=positive, default=10, help="QUIC: đổi địa chỉ sau handshake (giây)")
    p.add_argument("--disable-after", type=positive, default=16, help="Migration: tắt đường A (giây)")
    p.add_argument("--migration-rate", type=rate, default="20mbit", help="Băng thông riêng bài migration")
    p.add_argument("--out", type=Path, help="Thư mục mới; mặc định data/week8/<timestamp>-<id>")
    p.add_argument("--dry-run", action="store_true", help="In kế hoạch, không tạo file hoặc thay đổi mạng")
    a = p.parse_args()
    try:
        a.loss_list = [number(x.strip()) for x in a.loss_list.split(",")]
    except argparse.ArgumentTypeError as e:
        p.error(str(e))
    if a.loss > 100 or any(x > 100 for x in a.loss_list):
        p.error("Tỉ lệ mất gói phải nằm trong [0, 100]")
    if len(set(a.loss_list)) != len(a.loss_list):
        p.error("--loss-list không được có mức trùng nhau")
    if a.runs < 1 or a.warmups < 0:
        p.error("--runs >= 1 và --warmups >= 0")
    if a.mode in ("migration", "all") and not (a.switch_after < a.migration_after < a.disable_after < a.timeout):
        p.error("Cần switch-after < migration-after < disable-after < timeout")
    a.out = (a.out or ROOT / "data/week8" / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6])).resolve()
    return a


def plan(a):
    modes = list(MODES[:-1]) if a.mode == "all" else [a.mode]
    items = []
    for mode in modes:
        losses = sorted(a.loss_list) if mode == "sweep" else [0 if mode == "baseline" else a.loss]
        for loss in losses:
            items.append(dict(mode=mode, loss_pct=loss,
                              delay="0ms" if mode == "baseline" else a.delay,
                              rate=a.migration_rate if mode == "migration" else a.rate,
                              runs=1 if mode == "migration" else a.runs))
    return items


class Lab:
    def __init__(self, out):
        token = uuid.uuid4().hex[:8]
        self.client, self.server = f"q8-{token}-c", f"q8-{token}-s"
        self.out = out
        self.created = []
        self.processes = []
        self.links = []
        self.capture = None

    def ns(self, side, *cmd):
        return ["ip", "netns", "exec", getattr(self, side), *map(str, cmd)]

    def command(self, side, *cmd):
        return run(self.ns(side, *cmd))

    def spawn(self, argv, stdout, stderr=None, env=None):
        with stdout.open("w") as out:
            if stderr:
                with stderr.open("w") as err:
                    p = sp.Popen(list(map(str, argv)), stdout=out, stderr=err, env=env, start_new_session=True)
            else:
                p = sp.Popen(list(map(str, argv)), stdout=out, stderr=sp.STDOUT, env=env, start_new_session=True)
        self.processes.append(p)
        return p

    @staticmethod
    def stop(p, sig=signal.SIGTERM):
        if p.poll() is None:
            os.killpg(p.pid, sig)
            try:
                p.wait(timeout=5)
            except sp.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()

    def setup(self):
        for ns in (self.client, self.server):
            run(["ip", "netns", "add", ns])
            self.created.append(ns)
        write_json(self.out / "namespaces.json", dict(client=self.client, server=self.server))
        for side in ("client", "server"):
            self.command(side, "ip", "link", "set", "lo", "up")
        # Create veth directly inside owned namespaces: no host interface to leak.
        for tag, subnet in (("a", 1), ("b", 2)):
            cli, srv = f"veth-{tag}-cli", f"veth-{tag}-srv"
            self.command("client", "ip", "link", "add", cli, "type", "veth", "peer", "name", srv,
                         "netns", self.server)
            for side, dev, host in (("client", cli, 1), ("server", srv, 2)):
                self.command(side, "ip", "addr", "add", f"10.0.{subnet}.{host}/30", "dev", dev)
                self.command(side, "ip", "link", "set", dev, "up")
                self.command(side, "ethtool", "-K", dev, "tso", "off", "gso", "off", "gro", "off")
                (self.out / f"offload-{dev}.txt").write_text(self.command(side, "ethtool", "-k", dev))
                self.links.append((side, dev))
        self.command("server", "ip", "addr", "add", "10.0.0.2/32", "dev", "lo")
        self.reset_route()
        runtime = self.out / "runtime"
        runtime.mkdir()
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "7",
             "-keyout", runtime / "server.key", "-out", runtime / "server.crt", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:10.0.0.2"])
        self.cert = runtime / "server.crt"
        config = ('{\n admin off\n servers {\n  protocols h2 h3\n }\n}\n'
                  'https://localhost:4433 {\n bind 10.0.0.2\n'
                  f' tls "{self.cert}" "{runtime / "server.key"}" {{\n  protocols tls1.2 tls1.3\n }}\n'
                  f' root * "{ROOT / "server-files"}"\n file_server\n}}\n')
        (runtime / "Caddyfile").write_text(config)
        env = dict(os.environ, XDG_DATA_HOME=str(runtime / "caddy-data"), XDG_CONFIG_HOME=str(runtime / "caddy-config"))
        self.caddy = self.spawn(self.ns("server", CADDY, "run", "--config", runtime / "Caddyfile",
                                      "--adapter", "caddyfile"), runtime / "caddy.log", env=env)
        for _ in range(50):
            if self.caddy.poll() is not None:
                raise RuntimeError(f"Caddy không khởi động; xem {runtime / 'caddy.log'}")
            listening = self.command("server", "ss", "-ltnH")
            if "10.0.0.2:4433" in listening:
                break
            time.sleep(.1)
        else:
            raise RuntimeError("Caddy chưa mở cổng 4433")

    def reset_route(self):
        self.command("client", "ip", "link", "set", "veth-a-cli", "up")
        self.command("client", "ip", "route", "replace", "10.0.0.2/32", "via", "10.0.1.2",
                     "dev", "veth-a-cli", "src", "10.0.1.1")

    def network(self, condition, directory):
        self.reset_route()
        for side, dev in self.links:
            cmd = ["tc", "qdisc", "replace", "dev", dev, "root", "netem", "limit", "10000",
                   "delay", condition["delay"], "loss", f'{condition["loss_pct"]:g}%']
            if condition["rate"] != "unlimited":
                cmd += ["rate", condition["rate"]]
            self.command(side, *cmd)
            (directory / f"netem-{dev}.json").write_text(self.command(side, "tc", "-s", "-j", "qdisc", "show", "dev", dev))
        time.sleep(.2)

    def network_counters(self, directory):
        for side, dev in self.links:
            (directory / f"netem-final-{dev}.json").write_text(
                self.command(side, "tc", "-s", "-j", "qdisc", "show", "dev", dev))

    def start_capture(self, directory):
        log = directory / "tcpdump.log"
        self.capture = self.spawn(self.ns("server", "tcpdump", "--immediate-mode", "-B", "4096",
                                          "-i", "any", "-nn", "-s", "0", "-U", "-Z", "root",
                                          "-w", directory / "capture.pcap", "port", "4433"), log)
        for _ in range(50):
            if self.capture.poll() is not None:
                raise RuntimeError(f"tcpdump thất bại: {log}")
            if "listening on" in log.read_text():
                return
            time.sleep(.1)
        raise RuntimeError("tcpdump chưa sẵn sàng")

    def stop_capture(self):
        if self.capture:
            time.sleep(.1)
            self.stop(self.capture, signal.SIGINT)
            self.capture = None

    def curl_command(self, protocol, url, output=None):
        options = ["--http2", "--tlsv1.2", "--tls-max", "1.2"] if protocol == "h2" else ["--http3-only"]
        return self.ns("client", CURL, *options, "--noproxy", "*", "--resolve", "localhost:4433:10.0.0.2",
                       "--cacert", self.cert, "--fail", "--silent", "--show-error",
                       *( ["--output", str(output)] if output else ["--out-null"] ),
                       "--write-out", "%{json}\n", url)

    def measure(self, a, condition, protocol, directory, capture, warmup=False):
        directory.mkdir(parents=True)
        url = "https://localhost:4433/objects/object-[01-20].bin"
        cmd = self.curl_command(protocol, url)
        cmd[cmd.index(str(CURL)) + 1:cmd.index(str(CURL)) + 1] = [
            "--parallel", "--parallel-max", "20", "--parallel-max-host", "1",
            "--max-time", str(a.timeout), "--connect-timeout", str(min(30, a.timeout))]
        env = dict(os.environ, SSLKEYLOGFILE=str(directory / "tls.keys"))
        env["LD_LIBRARY_PATH"] = f"{ROOT / 'tools/curl-h3/lib'}" + (f":{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else "")
        if capture:
            self.start_capture(directory)
        started = time.monotonic()
        timed_out = False
        try:
            proc = self.spawn(["timeout", "--signal=TERM", "--kill-after=2s", f"{a.timeout + 5}s", *cmd],
                              directory / "curl.jsonl", directory / "curl.stderr", env)
            # Blocking wait avoids the polling delay of Popen.wait(timeout) in measured wall time.
            code = proc.wait()
            timed_out = code in (124, 137)
        finally:
            elapsed = time.monotonic() - started
            self.stop_capture()
        result = dict(protocol=protocol, mode=condition["mode"], loss_pct=condition["loss_pct"],
                      expected_objects=20, expected_bytes=131072,
                      elapsed_ms=elapsed * 1000, exit_code=code, timed_out=timed_out, warmup=warmup)
        write_json(directory / "run.json", result)
        print(f'  {directory.relative_to(self.out)}: exit={code}, {elapsed:.2f}s', flush=True)
        if capture:
            packets(directory)

    def migration(self, a, condition, directory):
        original = ROOT / "server-files/week6-large.bin"
        expected_hash = sha256(original)
        result = dict(original_bytes=original.stat().st_size, original_sha256=expected_hash)
        for protocol in ("h3", "h2"):
            self.reset_route()
            dest = directory / protocol
            dest.mkdir()
            env = dict(os.environ, SSLKEYLOGFILE=str(dest / "tls.keys"))
            env["LD_LIBRARY_PATH"] = f"{ROOT / 'tools/curl-h3/lib'}" + (f":{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else "")
            download = dest / "download"
            download.mkdir()
            target = download / original.name
            if protocol == "h3":
                env["LD_LIBRARY_PATH"] = f"{ROOT / 'tools/ngtcp2-week8/lib'}:{env['LD_LIBRARY_PATH']}"
                cmd = self.ns("client", GTLS, "--quiet", "--no-gso", "--change-local-addr", f"{round(a.migration_after * 1000)}ms",
                              "--exit-on-all-streams-close", "--download", download,
                              "10.0.0.2", "4433", f"https://localhost:4433/{original.name}")
            else:
                cmd = self.curl_command("h2", f"https://localhost:4433/{original.name}", target)
                cmd += ["--interface", "10.0.1.1", "--max-time", str(a.timeout),
                        "--speed-limit", "1", "--speed-time", "10"]
            self.start_capture(dest)
            start = time.monotonic()
            proc = self.spawn(cmd, dest / "client.log", env=env)
            events = []
            switched = disabled = False
            try:
                while proc.poll() is None:
                    elapsed = time.monotonic() - start
                    if elapsed >= a.switch_after and not switched:
                        self.command("client", "ip", "route", "replace", "10.0.0.2/32", "via", "10.0.2.2",
                                     "dev", "veth-b-cli", "src", "10.0.2.1")
                        events.append(dict(event="route_to_B", elapsed_s=time.monotonic() - start))
                        switched = True
                    if elapsed >= a.disable_after and not disabled:
                        self.command("client", "ip", "link", "set", "veth-a-cli", "down")
                        events.append(dict(event="disable_A", elapsed_s=time.monotonic() - start))
                        disabled = True
                    if elapsed >= a.timeout:
                        self.stop(proc)
                        events.append(dict(event="timeout", elapsed_s=elapsed))
                        break
                    time.sleep(.05)
            finally:
                self.stop(proc)
                self.stop_capture()
            write_json(dest / "events.json", events)
            row = dict(exit_code=proc.returncode, route_switched=switched, old_path_disabled=disabled,
                       elapsed_s=time.monotonic() - start, bytes=target.stat().st_size if target.exists() else 0,
                       sha256=sha256(target) if target.exists() else None)
            row["download_matches"] = row["sha256"] == expected_hash
            row["client_errors"] = sorted(set(re.findall(r"ERR_[A-Z_]+", (dest / "client.log").read_text(errors="replace"))))
            if row["client_errors"]:
                row["inconclusive_reason"] = "Client báo lỗi: " + ", ".join(row["client_errors"])
            elif not disabled:
                row["inconclusive_reason"] = "Lượt tải kết thúc trước khi tắt mạng A; giảm migration-rate hoặc đổi mốc thời gian."
            packets(dest)
            row["packet_evidence"] = migration_evidence(dest, protocol)
            result[protocol] = row
            print(f'  migration {protocol}: exit={proc.returncode}, bytes={row["bytes"]}', flush=True)
            if protocol == "h2" and disabled:
                retry = directory / "h2-retry"
                retry.mkdir()
                self.start_capture(retry)
                retry_target = retry / original.name
                cmd = self.curl_command("h2", f"https://localhost:4433/{original.name}", retry_target)
                cmd += ["--interface", "10.0.2.1", "--max-time", str(a.timeout)]
                try:
                    proc = self.spawn(cmd, retry / "curl.jsonl", retry / "curl.stderr",
                                      dict(os.environ, SSLKEYLOGFILE=str(retry / "tls.keys")))
                    try:
                        proc.wait(timeout=a.timeout + 5)
                    except sp.TimeoutExpired:
                        self.stop(proc)
                finally:
                    self.stop_capture()
                packets(retry)
                result["h2_retry"] = dict(exit_code=proc.returncode,
                                          download_matches=retry_target.exists() and sha256(retry_target) == expected_hash,
                                          packet_evidence=migration_evidence(retry, "h2"))
        quic = result["h3"]
        evidence = quic["packet_evidence"]
        result["verified"] = (quic["download_matches"] and quic["old_path_disabled"] and quic["exit_code"] == 0 and not quic["client_errors"]
                              and evidence["both_client_ips"] and evidence["port_changed"]
                              and evidence["single_quic_connection"] and evidence["path_challenge"]
                              and evidence["path_response"] and evidence["no_initial_on_B"]
                              and not result["h2"]["download_matches"] and result["h2"]["old_path_disabled"]
                              and result["h2"]["exit_code"] != 0
                              and result["h2"]["packet_evidence"]["http2_tls12"]
                              and result["h2"]["packet_evidence"]["syn_from_A"]
                              and result.get("h2_retry", {}).get("download_matches", False)
                              and result["h2_retry"]["exit_code"] == 0
                              and result["h2_retry"]["packet_evidence"]["http2_tls12"]
                              and result["h2_retry"]["packet_evidence"]["syn_from_B"])
        write_json(directory / "migration-summary.json", result)
        return result["verified"]

    def cleanup(self):
        for proc in reversed(self.processes):
            self.stop(proc, signal.SIGINT if proc is self.capture else signal.SIGTERM)
        errors = []
        for ns in reversed(self.created):
            try:
                run(["ip", "netns", "delete", ns])
            except Exception as exc:
                errors.append(f"{ns}: {exc}")
        write_json(self.out / "cleanup.json", dict(namespaces=self.created, removed=not errors, errors=errors))
        if errors:
            raise RuntimeError("Không dọn được namespace: " + "; ".join(errors))


PACKET_FIELDS = ["frame.number", "frame.time_relative", "ip.src", "ip.dst", "tcp.srcport", "udp.srcport",
                 "tcp.stream", "tcp.flags.syn", "tls.handshake.type", "tls.handshake.version",
                 "tls.handshake.extensions_alpn_str", "http2.streamid", "quic.connection.number",
                 "quic.long.packet_type", "quic.dcid", "quic.stream.stream_id", "quic.frame_type", "_ws.col.Info"]


def packets(directory):
    command = ["tshark", "-r", directory / "capture.pcap", "-d", "tcp.port==4433,tls",
               "-d", "udp.port==4433,quic", "-o", f'tls.keylog_file:{directory / "tls.keys"}',
               "-T", "fields", "-E", "header=y", "-E", "quote=d"]
    for field in PACKET_FIELDS:
        command += ["-e", field]
    with (directory / "packets.tsv").open("w") as output, (directory / "tshark.stderr").open("w") as error:
        proc = sp.run(list(map(str, command)), stdout=output, stderr=error, timeout=120)
    if proc.returncode:
        raise RuntimeError(f"Không phân tích được pcap: {directory / 'tshark.stderr'}")


def migration_evidence(directory, protocol):
    with (directory / "packets.tsv").open() as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    clients = [r for r in rows if r["ip.src"] in ("10.0.1.1", "10.0.2.1")]
    if protocol == "h2":
        server_hello = [r for r in rows if r["ip.src"] == "10.0.0.2" and "2" in r["tls.handshake.type"].split(",")]
        return dict(http2_tls12=any(r["tls.handshake.version"] == "0x0303" and r["tls.handshake.extensions_alpn_str"] == "h2" for r in server_hello)
                    and any(r["http2.streamid"] for r in rows),
                    syn_from_A=any(r["ip.src"] == "10.0.1.1" and r["tcp.flags.syn"] == "True" for r in clients),
                    syn_from_B=any(r["ip.src"] == "10.0.2.1" and r["tcp.flags.syn"] == "True" for r in clients),
                    tcp_streams=sorted({v for r in rows for v in r["tcp.stream"].split(",") if v}))
    ports = {ip: {r["udp.srcport"] for r in clients if r["ip.src"] == ip and r["udp.srcport"]}
             for ip in ("10.0.1.1", "10.0.2.1")}
    connections = {v for r in rows for v in r["quic.connection.number"].split(",") if v}
    types = {v for r in rows for v in r["quic.frame_type"].split(",") if v}
    return dict(both_client_ips=all(ports.values()),
                port_changed=bool(ports["10.0.1.1"] and ports["10.0.2.1"] and ports["10.0.1.1"].isdisjoint(ports["10.0.2.1"])),
                source_ports={ip: sorted(values) for ip, values in ports.items()},
                single_quic_connection=len(connections) == 1, connection_numbers=sorted(connections),
                path_challenge=any(int(v, 0) == 0x1a for v in types),
                path_response=any(int(v, 0) == 0x1b for v in types),
                no_initial_on_B=not any(r["ip.src"] == "10.0.2.1" and "0" in r["quic.long.packet_type"].split(",") for r in rows))


def preflight(a):
    if os.geteuid() != 0:
        raise RuntimeError("Chạy bằng sudo (cần quyền tạo namespace và cấu hình tc).")
    for tool in ("ip", "tc", "ethtool", "openssl", "tcpdump", "tshark", "ss", "timeout"):
        if not shutil.which(tool):
            raise RuntimeError(f"Thiếu công cụ: {tool}")
    for exe in (CURL, CADDY):
        if not os.access(exe, os.X_OK):
            raise RuntimeError(f"Thiếu chương trình: {exe}")
    version = run([CURL, "-V"])
    if "HTTP2" not in version or "HTTP3" not in version or "GnuTLS" not in version:
        raise RuntimeError("Cần curl GnuTLS hỗ trợ cả HTTP2 và HTTP3 như cấu hình lab.")
    run([sys.executable, "-c", "import matplotlib,numpy"])
    for i in range(1, 21):
        file = ROOT / f"server-files/objects/object-{i:02d}.bin"
        if not file.exists() or file.stat().st_size != 131072:
            raise RuntimeError(f"Cần đối tượng 128 KiB: {file}")
    if a.mode in ("migration", "all"):
        if not GTLS.is_file():
            raise RuntimeError("Thiếu gtlsclient; chạy bash scripts/setup-week8-migration.sh trước.")
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = f"{ROOT / 'tools/ngtcp2-week8/lib'}:{ROOT / 'tools/curl-h3/lib'}" + (f":{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else "")
        run([GTLS, "--help"], env=env)
        if not (ROOT / "server-files/week6-large.bin").is_file():
            raise RuntimeError("Thiếu server-files/week6-large.bin của tuần 6")


def main():
    a = arguments()
    schedule = plan(a)
    config = {**vars(a), "out": str(a.out), "plan": schedule,
              "network_note": "loss, delay, rate áp độc lập ở mỗi chiều; baseline ép loss=0, delay=0ms",
              "randomness_note": "Netem dùng mất gói ngẫu nhiên; tái lập quy trình, không bảo đảm kết quả số giống từng bit."}
    if a.dry_run:
        print(json.dumps(config, indent=2, ensure_ascii=False))
        return 0
    preflight(a)
    a.out.mkdir(parents=True, exist_ok=False)
    write_json(a.out / "config.json", config)
    (a.out / "curl-version.txt").write_text(run([CURL, "-V"]))
    (a.out / "caddy-version.txt").write_text(run([CADDY, "version"]))
    (a.out / "kernel.txt").write_text(run(["uname", "-a"]))
    source_paths = [Path(__file__), ROOT / "scripts/week8-analyze.py", ROOT / "scripts/run-experiment.sh", CURL, CADDY]
    if a.mode in ("migration", "all"):
        (a.out / "gtlsclient-version.txt").write_text("ngtcp2 v1.16.0, GnuTLS example client; see scripts/setup-week8-migration.sh\n")
        source_paths.append(GTLS)
    write_json(a.out / "source-sha256.json", {str(p.relative_to(ROOT)): sha256(p) for p in source_paths})
    write_json(a.out / "objects-sha256.json", {p.name: sha256(p) for p in sorted((ROOT / "server-files/objects").glob("object-*.bin"))})
    lab = Lab(a.out)
    status = dict(status="running", all_migration_checks_passed=True)
    print(f"Kết quả: {a.out}", flush=True)
    def interrupt(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupt)
    try:
        lab.setup()
        for c in schedule:
            directory = a.out / c["mode"] / f'loss-{c["loss_pct"]:g}'
            directory.mkdir(parents=True)
            lab.network(c, directory)
            print(f'{c["mode"]}: loss={c["loss_pct"]:g}%, delay={c["delay"]}, rate={c["rate"]}', flush=True)
            if c["mode"] == "migration":
                status["all_migration_checks_passed"] &= lab.migration(a, c, directory)
                lab.network_counters(directory)
                continue
            for warm in range(1, a.warmups + 1):
                for protocol in ("h2", "h3"):
                    lab.measure(a, c, protocol, directory / "warmups" / protocol / f"run-{warm:03d}", False, True)
            for n in range(1, a.runs + 1):
                for protocol in (("h2", "h3") if n % 2 else ("h3", "h2")):
                    lab.measure(a, c, protocol, directory / protocol / f"run-{n:03d}", n == 1 or a.pcap == "all")
            lab.network_counters(directory)
        sp.run([sys.executable, str(ROOT / "scripts/week8-analyze.py"), str(a.out)], check=True)
        status["validation"] = json.loads((a.out / "validation.json").read_text())
        if status["validation"]["invalid_runs"]:
            status["status"] = "invalid_evidence"
            return 2
        status["status"] = "completed" if status["all_migration_checks_passed"] else "inconclusive_migration"
        if status["validation"]["pcap_decode_failures"] and status["status"] == "completed":
            status["status"] = "completed_with_pcap_warnings"
        return 0 if status["all_migration_checks_passed"] else 2
    except KeyboardInterrupt:
        status["status"] = "interrupted"
        print("Đã ngắt; đang dọn môi trường riêng.", file=sys.stderr)
        return 130
    except Exception as exc:
        status.update(status="error", error=str(exc))
        raise
    finally:
        # Further Ctrl+C must not skip cleanup.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            lab.cleanup()
        finally:
            write_json(a.out / "status.json", status)
            if os.environ.get("SUDO_UID"):
                uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
                for path in [a.out, *a.out.rglob("*")]:
                    os.chown(path, uid, gid)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, FileExistsError, sp.CalledProcessError) as exc:
        print(f"LỖI: {exc}", file=sys.stderr)
        if isinstance(exc, sp.CalledProcessError) and exc.stderr:
            print(exc.stderr, file=sys.stderr)
        sys.exit(1)
