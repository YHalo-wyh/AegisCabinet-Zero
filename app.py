from __future__ import annotations

import hashlib
import hmac
import html
import json
import math
import secrets
import statistics
import time
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Dict, List, Optional, Tuple

import streamlit as st


# ============================================================
# AegisCabinet-Zero
# 零信任校园智能外卖柜仿真系统
#
# 运行方式：
#   streamlit run app.py
#
# 本文件是完整闭环单文件实现：
# 1. Schnorr 零知识证明三步握手
# 2. 常量时间比较与时间侧信道演示
# 3. 固件 Stack Canary 溢出防护模拟
# 4. 4x4 数字化双胞胎格口矩阵
# 5. 混沌工程攻击按钮、风控熵值与审计日志
#
# UI 设计参考：
# - ui-ux-pro-max-skill: HUD / Sci-Fi FUI、Dark OLED、Bento Grid、Micro-interactions
# - react-bits: DotGrid、ElectricBorder、GlareHover、FaultyTerminal 的动效思想
# ============================================================

APP_TITLE = "AegisCabinet-Zero"
APP_SUBTITLE = "校园零信任智能外卖柜攻防仿真系统"

# Schnorr ZKP 教学群参数。
# p = 2q + 1，q 为素数，g 属于 p 下 q 阶子群，满足 g^q mod p == 1。
# 这些数足够演示数学闭环，但不是生产级安全参数。真实系统应使用成熟椭圆曲线或大素数群。
ZKP_P = 2027
ZKP_Q = 1013
ZKP_G = 4

LOCKER_COUNT = 16
LOCKER_LABELS = [f"{row}{col}" for row in "ABCD" for col in range(1, 5)]
LOCKED = 0
UNLOCKED = 1
SELF_LOCKED = 2
LOCKER_STATE_TEXT = {
    LOCKED: ("已锁定", "门锁闭合"),
    UNLOCKED: ("验证通过", "格口弹开"),
    SELF_LOCKED: ("安全自锁", "攻击拦截"),
}

CANARY_BYTES = b"AEGIS_CANARY_V1"
FIRMWARE_MAGIC = b"AEGISFW"
FIRMWARE_VERSION = 1
MAX_FIRMWARE_PAYLOAD = 64
LOG_LIMIT = 100
HISTORY_LIMIT = 160
LATENCY_LIMIT = 80
TIMING_REPEATS = 4
REPLAY_WINDOW_SECONDS = 30.0
SIMULATED_REPLAY_AGE_SECONDS = 60.0


class SecurityMemoryError(Exception):
    """固件解析安全异常。

    当边缘外卖柜固件解析外部报文时，攻击者可能构造超长 payload 试图覆盖栈帧、
    修改返回地址或破坏控制流。Stack Canary 的思想是在敏感栈区域旁放置一段守护字节，
    函数返回前检查它是否仍然完整。若 payload 溢出并破坏 Canary，系统立即中止解析，
    进入硬核自锁状态，而不是继续执行不可信内存。
    """


@dataclass(frozen=True)
class ZKPSession:
    locker: str
    pickup_hash_short: str
    public_y: int
    commitment_x: int
    challenge_c: int
    response_s: int
    left_value: int
    right_value: int
    nonce: str
    timestamp: float
    accepted: bool
    reason: str


@dataclass(frozen=True)
class PlainSession:
    locker: str
    device_id: str
    pickup_code: str
    timestamp: float
    nonce: str
    latency_ms: float
    matched_prefix: int
    accepted: bool
    reason: str


@dataclass(frozen=True)
class FirmwarePacket:
    version: int
    declared_len: int
    payload_len: int
    payload_sha256_short: str
    crc_short: str


def clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def now_ts() -> float:
    return time.time()


def time_label(ts: Optional[float] = None) -> str:
    stamp = now_ts() if ts is None else ts
    return datetime.fromtimestamp(stamp).strftime("%H:%M:%S")


def short_hex(value: str, head: int = 8, tail: int = 6) -> str:
    if len(value) <= head + tail:
        return value
    return f"{value[:head]}...{value[-tail:]}"


def normalize_code(raw: str) -> str:
    return "".join(ch for ch in raw if ch.isdigit())[:6]


def locker_index(label: str) -> int:
    return LOCKER_LABELS.index(label)


def demo_pickup_codes() -> Dict[str, str]:
    # 固定演示码，便于课堂复现。真实系统应由后端订单系统动态下发并及时失效。
    return {
        "A1": "284913",
        "A2": "615204",
        "A3": "907461",
        "A4": "138620",
        "B1": "471926",
        "B2": "850317",
        "B3": "266409",
        "B4": "730582",
        "C1": "194708",
        "C2": "609341",
        "C3": "382615",
        "C4": "945230",
        "D1": "527094",
        "D2": "318756",
        "D3": "764028",
        "D4": "402681",
    }


def init_state() -> None:
    if "pickup_codes" not in st.session_state:
        st.session_state.pickup_codes = demo_pickup_codes()
    if "locker_states" not in st.session_state:
        st.session_state.locker_states = [LOCKED for _ in range(LOCKER_COUNT)]
    if "selected_locker" not in st.session_state:
        st.session_state.selected_locker = "A1"
    if "audit_logs" not in st.session_state:
        st.session_state.audit_logs = deque(maxlen=LOG_LIMIT)
    if "request_history" not in st.session_state:
        st.session_state.request_history = deque(maxlen=HISTORY_LIMIT)
    if "attack_history" not in st.session_state:
        st.session_state.attack_history = deque(maxlen=HISTORY_LIMIT)
    if "latency_points" not in st.session_state:
        st.session_state.latency_points = deque(maxlen=LATENCY_LIMIT)
    if "used_transcripts" not in st.session_state:
        st.session_state.used_transcripts = set()
    if "last_zkp_session" not in st.session_state:
        st.session_state.last_zkp_session = None
    if "last_plain_session" not in st.session_state:
        st.session_state.last_plain_session = None
    if "last_attack_feedback" not in st.session_state:
        st.session_state.last_attack_feedback = None
    if "trace_rows" not in st.session_state:
        st.session_state.trace_rows = deque(maxlen=240)
    if "last_replay_packet" not in st.session_state:
        st.session_state.last_replay_packet = None
    if "last_plain_replay_packet" not in st.session_state:
        st.session_state.last_plain_replay_packet = None
    if "last_zkp_replay_packet" not in st.session_state:
        st.session_state.last_zkp_replay_packet = None
    if "last_replay_steps" not in st.session_state:
        st.session_state.last_replay_steps = []
    if "last_replay_target_locker" not in st.session_state:
        st.session_state.last_replay_target_locker = st.session_state.selected_locker
    if "last_replay_mode" not in st.session_state:
        st.session_state.last_replay_mode = "zero_trust"
    if "last_replay_verdict" not in st.session_state:
        st.session_state.last_replay_verdict = None
    if "last_timing_summary" not in st.session_state:
        st.session_state.last_timing_summary = None
    if "last_overflow_locker" not in st.session_state:
        st.session_state.last_overflow_locker = st.session_state.selected_locker
    if "last_overflow_mode" not in st.session_state:
        st.session_state.last_overflow_mode = "zero_trust"
    if "last_payload_rows" not in st.session_state:
        st.session_state.last_payload_rows = []
    if "last_event" not in st.session_state:
        st.session_state.last_event = "SYSTEM_BOOT"
    if "risk_score" not in st.session_state:
        st.session_state.risk_score = 0
    if "constant_time_enabled" not in st.session_state:
        st.session_state.constant_time_enabled = True
    if "zero_trust_enabled" not in st.session_state:
        st.session_state.zero_trust_enabled = True
    if "secure_counter" not in st.session_state:
        st.session_state.secure_counter = 0
    if "attack_counter" not in st.session_state:
        st.session_state.attack_counter = 0
    if "blocked_counter" not in st.session_state:
        st.session_state.blocked_counter = 0
    if "accepted_counter" not in st.session_state:
        st.session_state.accepted_counter = 0


def reset_state() -> None:
    st.session_state.locker_states = [LOCKED for _ in range(LOCKER_COUNT)]
    st.session_state.audit_logs = deque(maxlen=LOG_LIMIT)
    st.session_state.request_history = deque(maxlen=HISTORY_LIMIT)
    st.session_state.attack_history = deque(maxlen=HISTORY_LIMIT)
    st.session_state.latency_points = deque(maxlen=LATENCY_LIMIT)
    st.session_state.used_transcripts = set()
    st.session_state.last_zkp_session = None
    st.session_state.last_plain_session = None
    st.session_state.last_attack_feedback = None
    st.session_state.trace_rows = deque(maxlen=240)
    st.session_state.last_replay_packet = None
    st.session_state.last_plain_replay_packet = None
    st.session_state.last_zkp_replay_packet = None
    st.session_state.last_replay_steps = []
    st.session_state.last_replay_target_locker = st.session_state.selected_locker
    st.session_state.last_replay_mode = "zero_trust" if st.session_state.zero_trust_enabled else "plain"
    st.session_state.last_replay_verdict = None
    st.session_state.last_timing_summary = None
    st.session_state.last_overflow_locker = st.session_state.selected_locker
    st.session_state.last_overflow_mode = "zero_trust" if st.session_state.zero_trust_enabled else "plain"
    st.session_state.last_payload_rows = []
    st.session_state.last_event = "SYSTEM_RESET"
    st.session_state.risk_score = 0
    st.session_state.secure_counter = 0
    st.session_state.attack_counter = 0
    st.session_state.blocked_counter = 0
    st.session_state.accepted_counter = 0


def mark_locker(label: str, state: int) -> None:
    st.session_state.locker_states[locker_index(label)] = state


def locker_state_label(label: str) -> str:
    state = st.session_state.locker_states[locker_index(label)]
    state_code, state_text = LOCKER_STATE_TEXT[state]
    return f"{state_code} · {state_text}"


def push_log(level: str, title: str, message: str, **fields: object) -> None:
    st.session_state.audit_logs.appendleft(
        {
            "ts": now_ts(),
            "level": level,
            "title": title,
            "message": message,
            "fields": fields,
        }
    )
    st.session_state.last_event = title


def push_trace(stage: str, detail: str, **fields: object) -> None:
    st.session_state.trace_rows.appendleft(
        {
            "ts": now_ts(),
            "stage": stage,
            "detail": detail,
            "fields": fields,
        }
    )


def record_request(
    *,
    locker: str,
    event_type: str,
    accepted: bool,
    reason: str,
    attack: bool,
    latency_ms: Optional[float] = None,
    risk_delta: int = 0,
) -> None:
    st.session_state.request_history.appendleft(
        {
            "ts": now_ts(),
            "locker": locker,
            "event_type": event_type,
            "accepted": accepted,
            "reason": reason,
            "attack": attack,
            "latency_ms": latency_ms,
            "risk_delta": risk_delta,
        }
    )
    st.session_state.risk_score = int(clamp(st.session_state.risk_score + risk_delta, 0, 100))
    if attack:
        st.session_state.attack_counter += 1
    if attack and not accepted:
        st.session_state.blocked_counter += 1
    if accepted:
        st.session_state.accepted_counter += 1


def compute_entropy_health() -> Tuple[float, str]:
    """计算信道健康熵值。

    信息熵用来观察最近请求是否多样且稳定。若请求全部集中在同一攻击标签、
    失败率很高或攻击占比很高，则说明信道正在被探测，健康值会下降。
    """

    recent = list(st.session_state.request_history)[:60]
    if not recent:
        return 100.0, "稳定"

    total = len(recent)
    attack_rate = sum(1 for item in recent if item["attack"]) / total
    reject_rate = sum(1 for item in recent if not item["accepted"]) / total

    # 冷启动阶段样本很少，单一的“正常成功”请求会天然表现为低熵。
    # 这不是攻击迹象，因此优先用攻击率、拒绝率和风险分作为健康度依据，
    # 避免课堂演示中第一次成功取件就被误标为“锁定”。
    if total < 4:
        health = clamp(
            100 - 45 * attack_rate - 40 * reject_rate - 0.2 * st.session_state.risk_score,
            0,
            100,
        )
        if health >= 80:
            return health, "稳定"
        if health >= 50:
            return health, "观察"
        if health >= 20:
            return health, "高危"
        return health, "锁定"

    labels = [
        f"{item['event_type']}|{'OK' if item['accepted'] else 'FAIL'}|{item['locker']}"
        for item in recent
    ]
    counts = Counter(labels)
    entropy = -sum((n / total) * math.log2(n / total) for n in counts.values())
    max_entropy = math.log2(max(len(counts), 2))
    entropy_norm = entropy / max_entropy if max_entropy else 1.0
    entropy_bonus = 12 * entropy_norm if attack_rate or reject_rate else 0
    health = clamp(
        100 + entropy_bonus - 52 * attack_rate - 42 * reject_rate - 0.2 * st.session_state.risk_score,
        0,
        100,
    )
    if health >= 80:
        status = "稳定"
    elif health >= 50:
        status = "观察"
    elif health >= 20:
        status = "高危"
    else:
        status = "锁定"
    return health, status


def compute_accuracy_metrics() -> Tuple[float, float]:
    recent = list(st.session_state.request_history)
    normal = [item for item in recent if not item["attack"]]
    attacks = [item for item in recent if item["attack"]]
    business_rate = (
        sum(1 for item in normal if item["accepted"]) / len(normal) * 100
        if normal
        else 100.0
    )
    defense_rate = (
        sum(1 for item in attacks if not item["accepted"]) / len(attacks) * 100
        if attacks
        else 100.0
    )
    return business_rate, defense_rate


def event_label(event_type: str) -> str:
    return {
        "zkp_unlock": "零知识取件",
        "plain_unlock": "普通柜取件",
        "timing_side_channel": "时间侧信道",
        "replay_attack": "重放攻击",
        "firmware_overflow": "固件溢出",
    }.get(event_type, event_type)


def reason_label(reason: str) -> str:
    return {
        "ZKP proof accepted": "零知识等式验证通过",
        "ZKP equation mismatch": "零知识等式不匹配",
        "Transcript nonce reused": "随机数已被使用",
        "Transcript 过期或 nonce 已使用": "报文过期或随机数已使用",
        "常量时间防护开启，时延曲线无可用前缀信号": "常量时间防护开启，时延无可用前缀信号",
        "非安全模式暴露前缀时延差": "非安全模式暴露前缀时延差",
        "普通柜逐位比较，攻击者已根据时延恢复取件码": "普通柜逐位比较，攻击者已根据时延恢复取件码",
        "零知识模式不暴露逐位比较接口，爆破在承诺阶段前被阻断": "零知识模式不暴露逐位比较接口，爆破在承诺阶段前被阻断",
        "零知识模式不暴露逐位比较接口，爆破在明文比较入口前被阻断": "零知识模式不暴露明文逐位比较入口，爆破无法获得前缀时延信号",
        "no transcript": "尚无可回放的认证记录",
        "plain replay accepted": "普通柜重放报文被接受",
        "plain replay code rejected": "普通柜明文取件码校验失败",
        "replay rejected": "重放报文已被拒绝",
        "replay accepted": "重放报文被接受",
        "replay device binding rejected": "设备编号绑定失败，不能跨柜复用旧报文",
        "replay locker binding rejected": "格口绑定失败，旧报文不属于当前目标格口",
        "replay digest mismatch": "报文摘要不匹配，疑似字段被篡改",
        "replay timestamp expired": "历史报文超过有效时间窗口",
        "replay digest reused": "认证摘要已经使用过，疑似重放",
        "replay zkp equation mismatch": "零知识等式验证失败",
        "plain overflow unsafe parse": "普通柜解析器缺少边界防护",
        "unexpected parse success": "异常载荷被解析通过",
    }.get(reason, reason)


def field_label(key: object) -> str:
    return {
        "locker": "格口",
        "X": "承诺 X",
        "c": "挑战 c",
        "s": "响应 s",
        "left": "左值",
        "right": "右值",
        "public_y": "公钥 y",
        "reason": "原因",
        "samples": "样本数",
        "mode": "比较模式",
        "last_latency_ms": "末次时延",
        "transcript": "认证摘要",
        "decision": "系统判定",
        "raw_len": "报文长度",
        "payload_len": "载荷长度",
        "payload_preview": "载荷片段",
        "payload_hex": "载荷十六进制",
        "canary_expected": "期望金丝雀",
        "canary_seen": "实际金丝雀",
        "crc": "CRC",
        "candidate": "候选输入",
        "matched_prefix": "匹配前缀",
        "latency_ms": "响应时长",
        "mode": "柜体模式",
        "device_id": "设备编号",
        "pickup_code": "取件码",
        "nonce": "随机数",
        "timestamp": "时间戳",
        "blocked_at": "阻断环节",
        "recovered_code": "恢复结果",
        "attempt": "尝试次数",
        "position": "爆破位数",
        "digit": "测试数字",
        "measurements": "测量次数",
        "avg_latency_ms": "平均时延",
        "min_latency_ms": "最小时延",
        "max_latency_ms": "最大时延",
        "stddev_ms": "时延波动",
        "blocked_reason": "阻断原因",
        "check": "检查项",
        "result": "检查结果",
        "source_locker": "报文所属格口",
        "target_locker": "攻击目标格口",
        "source_device_id": "报文设备编号",
        "target_device_id": "目标设备编号",
        "simulated_age_seconds": "模拟报文年龄",
        "window_seconds": "允许时间窗",
        "digest": "报文摘要",
        "stage_passed": "已通过步骤",
        "replay_guard": "重放保护",
        "magic_check": "Magic 检查",
        "version_check": "版本检查",
        "length_check": "长度检查",
        "canary_check": "金丝雀检查",
        "crc_check": "CRC 检查",
        "safe_mode": "安全解析模式",
    }.get(str(key), str(key))


def value_label(value: object) -> str:
    text = str(value)
    return {
        "BLOCK": "拦截",
        "WARN": "告警",
        "constant_time": "常量时间",
        "early_exit": "逐位早退",
        "plain": "普通外卖柜",
        "zero_trust": "零知识功能外卖柜",
        "timing_probe": "时延探测",
        "commitment": "承诺阶段",
        "no_plain_compare_api": "明文比较接口不存在",
        "device_binding": "设备编号绑定校验",
        "locker_binding": "格口绑定校验",
        "digest_mismatch": "报文摘要不匹配",
        "plaintext_compare": "明文取件码校验",
        "not_reached": "未执行到该步骤",
        "not_enabled": "未启用",
        "parse_packet": "报文解析",
        "zkp_equation": "零知识等式校验",
        "timestamp_window": "时间窗口",
        "digest_cache": "摘要缓存",
        "canary_check": "金丝雀检查",
        "length_check": "长度检查",
        "crc_check": "CRC 检查",
        "magic_check": "Magic 检查",
        "version_check": "版本检查",
        "PASS": "通过",
        "FAIL": "失败",
        "SKIP": "跳过",
        "OPEN": "打开",
        "CLOSED": "关闭",
        "LOCKDOWN": "自锁",
        "True": "是",
        "False": "否",
    }.get(text, reason_label(text))


def derive_private_x(locker: str, pickup_code: str) -> Tuple[int, str]:
    """把取件码映射为 Schnorr 私钥 x。

    物联网外卖柜不能把取件码明文发给云端，否则校园网抓包者可以直接复用。
    这里用带域分离的 SHA-256 哈希把“格口 + 取件码 + 系统盐”映射到 q 阶子群私钥。
    UI 只展示短哈希和公钥 y，不展示 x，从而体现“证明知道秘密，但不泄露秘密”的零知识思想。
    """

    material = f"AegisCabinet-Zero|{locker}|{pickup_code}|campus-salt-v1"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    x = int(digest, 16) % ZKP_Q
    if x == 0:
        x = 1
    return x, digest[:12]


def zkp_public_key(x: int) -> int:
    return pow(ZKP_G, x, ZKP_P)


def zkp_commitment() -> Tuple[int, int]:
    """节点生成 Schnorr 承诺。

    设备端选择随机 r，计算 X = g^r mod p。X 是公开承诺，不暴露私钥 x。
    若攻击者只看到 X，无法反推出 r 或取件码对应的 x。
    """

    r = secrets.randbelow(ZKP_Q - 1) + 1
    commitment_x = pow(ZKP_G, r, ZKP_P)
    return r, commitment_x


def zkp_challenge() -> int:
    """服务器生成随机挑战 c。

    挑战数让证明成为交互式协议。攻击者无法提前知道 c，因此不能提前伪造响应 s。
    """

    return secrets.randbelow(ZKP_Q - 1) + 1


def zkp_response(r: int, c: int, x: int) -> int:
    """节点计算响应 s = (r + c*x) mod q。"""

    return (r + c * x) % ZKP_Q


def zkp_verify(public_y: int, commitment_x: int, c: int, s: int) -> Tuple[bool, int, int]:
    """服务器校验 Schnorr 等式。

    验证公式：
        g^s mod p == X * y^c mod p

    左侧由响应 s 生成；右侧由公开承诺 X、公钥 y 和挑战 c 生成。
    若用户知道正确取件码映射出的私钥 x，等式成立；不知道 x 则几乎无法构造正确 s。
    """

    left = pow(ZKP_G, s, ZKP_P)
    right = (commitment_x * pow(public_y, c, ZKP_P)) % ZKP_P
    return hmac.compare_digest(str(left), str(right)), left, right


def transcript_id(locker: str, commitment_x: int, c: int, s: int, nonce: str) -> str:
    raw = f"{device_id_for(locker)}|{locker}|{commitment_x}|{c}|{s}|{nonce}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def device_id_for(locker: str) -> str:
    return f"AegisCabinet-{locker}-{locker_index(locker) + 1:02d}"


def plain_packet_id(locker: str, code: str, nonce: str, timestamp: float) -> str:
    raw = f"{device_id_for(locker)}|{locker}|{code}|{nonce}|{timestamp:.3f}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def plain_session_packet(session: PlainSession) -> Dict[str, object]:
    digest = plain_packet_id(session.locker, session.pickup_code, session.nonce, session.timestamp)
    return {
        "device_id": session.device_id,
        "locker": session.locker,
        "pickup_code": session.pickup_code,
        "timestamp": f"{session.timestamp:.3f}",
        "nonce": session.nonce,
        "digest": digest,
        "latency_ms": session.latency_ms,
        "matched_prefix": session.matched_prefix,
    }


def zkp_session_packet(session: ZKPSession) -> Dict[str, object]:
    digest = transcript_id(
        session.locker,
        session.commitment_x,
        session.challenge_c,
        session.response_s,
        session.nonce,
    )
    return {
        "device_id": device_id_for(session.locker),
        "locker": session.locker,
        "public_y": session.public_y,
        "X": session.commitment_x,
        "c": session.challenge_c,
        "s": session.response_s,
        "nonce": session.nonce,
        "timestamp": f"{session.timestamp:.3f}",
        "digest": digest,
    }


def reference_plain_packet(locker: str) -> Dict[str, object]:
    """生成当前目标格口的一条“正确普通柜报文”用于对照展示。

    它不写入 last_replay_packet，也不改变柜门状态，只说明服务器希望看到的 device_id、
    locker、pickup_code、nonce、timestamp 与 digest 应该如何绑定。攻击报文若来自别的格口，
    这里的 device_id 和 locker 会立刻不同。
    """

    code = st.session_state.pickup_codes[locker]
    timestamp = now_ts()
    nonce = secrets.token_hex(6)
    return {
        "device_id": device_id_for(locker),
        "locker": locker,
        "pickup_code": code,
        "timestamp": f"{timestamp:.3f}",
        "nonce": nonce,
        "digest": plain_packet_id(locker, code, nonce, timestamp),
        "latency_ms": "逐位比较会泄露时延",
        "matched_prefix": 6,
    }


def reference_zkp_packet(locker: str) -> Dict[str, object]:
    """生成当前目标格口的一条“正确零知识报文”用于对照展示。

    零知识认证的正确请求不是固定字符串。每一次都会重新产生随机承诺 X、随机挑战 c、
    响应 s、nonce 和 timestamp，因此右侧参考报文刷新后会变化。服务器接受的是“当前
    时间窗内、未使用过、设备/格口绑定正确、ZKP 等式成立”的一次性证明。
    """

    expected_code = st.session_state.pickup_codes[locker]
    x_expected, _ = derive_private_x(locker, expected_code)
    public_y = zkp_public_key(x_expected)
    r, commitment_x = zkp_commitment()
    c = zkp_challenge()
    s = zkp_response(r, c, x_expected)
    left = pow(ZKP_G, s, ZKP_P)
    right = (commitment_x * pow(public_y, c, ZKP_P)) % ZKP_P
    nonce = secrets.token_hex(8)
    timestamp = now_ts()
    return {
        "device_id": device_id_for(locker),
        "locker": locker,
        "public_y": public_y,
        "X": commitment_x,
        "c": c,
        "s": s,
        "nonce": nonce,
        "timestamp": f"{timestamp:.3f}",
        "digest": transcript_id(locker, commitment_x, c, s, nonce),
        "fresh_window": f"{REPLAY_WINDOW_SECONDS:.0f}s 内有效",
        "digest_cache": "必须未使用",
        "equation": f"{left} == {right}",
    }


def reference_packet_for(locker: str, zero_trust_enabled: bool) -> Dict[str, object]:
    return reference_zkp_packet(locker) if zero_trust_enabled else reference_plain_packet(locker)


def perform_zkp_unlock(locker: str, submitted_code: str) -> ZKPSession:
    """执行完整三步 Schnorr ZKP 正常取件流程。

    1. Client: 由输入取件码派生私钥 x 与公钥 y。
    2. Client: 生成随机 r 与承诺 X。
    3. Server: 生成挑战 c。
    4. Client: 计算响应 s。
    5. Server: 使用登记公钥 y_expected 验证 g^s == X*y^c。

    服务器只使用登记公钥，不接收明文取件码，因此即使攻击者监听网络，也拿不到取件秘密。
    """

    expected_code = st.session_state.pickup_codes[locker]
    x_client, pickup_hash_short = derive_private_x(locker, submitted_code)
    x_expected, _ = derive_private_x(locker, expected_code)
    public_y_expected = zkp_public_key(x_expected)

    r, commitment_x = zkp_commitment()
    c = zkp_challenge()
    s = zkp_response(r, c, x_client)
    accepted, left, right = zkp_verify(public_y_expected, commitment_x, c, s)
    nonce = secrets.token_hex(8)
    tid = transcript_id(locker, commitment_x, c, s, nonce)
    if tid in st.session_state.used_transcripts:
        accepted = False
        reason = "Transcript nonce reused"
    else:
        reason = "ZKP proof accepted" if accepted else "ZKP equation mismatch"
        if accepted:
            st.session_state.used_transcripts.add(tid)

    session = ZKPSession(
        locker=locker,
        pickup_hash_short=pickup_hash_short,
        public_y=public_y_expected,
        commitment_x=commitment_x,
        challenge_c=c,
        response_s=s,
        left_value=left,
        right_value=right,
        nonce=nonce,
        timestamp=now_ts(),
        accepted=accepted,
        reason=reason,
    )
    st.session_state.last_zkp_session = session
    packet = zkp_session_packet(session)
    st.session_state.last_zkp_replay_packet = packet
    st.session_state.last_replay_packet = packet
    return session


def secure_pickup_compare(candidate: str, expected: str, insecure_mode: bool = False) -> Tuple[bool, float, int]:
    """取件码常量时间比较器。

    安全模式使用 hmac.compare_digest，并人为补齐固定处理时间，使攻击者从响应时延中
    看不出“前几位是否猜对”。非安全演示模式故意逐字符比较并提前返回，同时对每个匹配
    字符 sleep 一小段时间，用来复现时间侧信道：猜对的前缀越长，响应越慢。
    """

    start = time.perf_counter()
    candidate_norm = normalize_code(candidate).ljust(6, "_")
    expected_norm = expected.ljust(6, "_")
    matched_prefix = 0

    if insecure_mode:
        ok = True
        for left, right in zip(candidate_norm, expected_norm):
            if left != right:
                ok = False
                break
            matched_prefix += 1
            time.sleep(0.0026)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return ok and candidate_norm == expected_norm, elapsed_ms, matched_prefix

    ok = hmac.compare_digest(candidate_norm.encode("utf-8"), expected_norm.encode("utf-8"))
    matched_prefix = sum(1 for left, right in zip(candidate_norm, expected_norm) if left == right)
    target_ms = 10.0
    elapsed_ms = (time.perf_counter() - start) * 1000
    if elapsed_ms < target_ms:
        time.sleep((target_ms - elapsed_ms) / 1000)
    # 为了让教学图呈现“常量时间直线”，记录固定目标值，而不是操作系统调度抖动。
    return ok, target_ms, matched_prefix


def measure_plain_candidate(candidate: str, expected: str, repeats: int = TIMING_REPEATS) -> Dict[str, object]:
    """对普通柜候选取件码做多次时延采样。

    时间侧信道攻击不是“看一次快慢就下结论”，而是对同一个候选输入重复请求，
    再比较平均时延、最小时延和最大时延。普通柜逐位早退时，正确前缀越长，
    每次比较都会多执行一次字符匹配，因此平均时延会稳定抬升。
    """

    latencies: List[float] = []
    prefixes: List[int] = []
    accepted = False
    for _ in range(repeats):
        ok, elapsed_ms, matched_prefix = secure_pickup_compare(
            candidate,
            expected,
            insecure_mode=True,
        )
        accepted = accepted or ok
        latencies.append(elapsed_ms)
        prefixes.append(matched_prefix)
    avg_latency = statistics.mean(latencies)
    return {
        "latencies": [round(value, 3) for value in latencies],
        "avg_latency_ms": round(avg_latency, 3),
        "min_latency_ms": round(min(latencies), 3),
        "max_latency_ms": round(max(latencies), 3),
        "stddev_ms": round(statistics.pstdev(latencies), 3) if len(latencies) > 1 else 0.0,
        "matched_prefix": max(prefixes),
        "accepted": accepted,
    }


def measure_zero_trust_probe(candidate: str, repeats: int = TIMING_REPEATS) -> Dict[str, object]:
    """模拟攻击者向零知识柜发送明文候选码时的固定时延。

    零知识柜的服务端接口不接收“候选明文取件码逐位比较”请求。攻击请求先经过
    请求类型检查，发现没有合法的 ZKP 承诺 X、挑战 c、响应 s，便在进入取件码比较
    前停止。为了避免攻击者从“拒绝速度”里继续找规律，网关把拒绝路径补齐到固定时延。
    """

    latencies: List[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        # 这里没有调用 secure_pickup_compare，也没有读取正确取件码；模拟的是协议网关预检查。
        target_ms = 10.0
        elapsed_ms = (time.perf_counter() - start) * 1000
        if elapsed_ms < target_ms:
            time.sleep((target_ms - elapsed_ms) / 1000)
        latencies.append(target_ms)
    return {
        "latencies": [round(value, 3) for value in latencies],
        "avg_latency_ms": 10.0,
        "min_latency_ms": 10.0,
        "max_latency_ms": 10.0,
        "stddev_ms": 0.0,
        "matched_prefix": 0,
        "accepted": False,
    }


def handle_plain_pickup(locker: str, code: str) -> PlainSession:
    code_norm = normalize_code(code)
    expected = st.session_state.pickup_codes[locker]
    ok, latency_ms, matched_prefix = secure_pickup_compare(
        code_norm,
        expected,
        insecure_mode=True,
    )
    session = PlainSession(
        locker=locker,
        device_id=device_id_for(locker),
        pickup_code=code_norm,
        timestamp=now_ts(),
        nonce=secrets.token_hex(6),
        latency_ms=round(latency_ms, 3),
        matched_prefix=matched_prefix,
        accepted=ok,
        reason="普通柜明文取件码比对通过" if ok else "普通柜明文取件码比对失败",
    )
    st.session_state.last_plain_session = session
    packet = plain_session_packet(session)
    st.session_state.last_replay_packet = packet
    st.session_state.last_plain_replay_packet = packet
    st.session_state.latency_points.append(
        {
            "sample": len(st.session_state.latency_points) + 1,
            "latency_ms": session.latency_ms,
            "matched_prefix": matched_prefix,
            "mode": "early_exit",
            "candidate": code_norm,
            "jitter_ms": round(max(session.latency_ms - 2, 0), 3),
            "accepted": ok,
        }
    )

    if ok:
        mark_locker(locker, UNLOCKED)
        risk_delta = -3
        level = "success"
        title = "普通外卖柜取件成功"
        message = "服务器直接接收明文取件码并逐位比较，格口弹开。"
    else:
        mark_locker(locker, LOCKED)
        risk_delta = 6
        level = "warn"
        title = "普通外卖柜取件失败"
        message = "取件码逐位比较失败，格口保持锁定。"

    record_request(
        locker=locker,
        event_type="plain_unlock",
        accepted=ok,
        reason=session.reason,
        attack=False,
        latency_ms=session.latency_ms,
        risk_delta=risk_delta,
    )
    push_log(
        level,
        title,
        message,
        locker=locker,
        mode="plain",
        device_id=session.device_id,
        pickup_code=code_norm,
        nonce=session.nonce,
        latency_ms=session.latency_ms,
        matched_prefix=matched_prefix,
    )
    push_trace(
        "普通柜取件",
        "明文取件码进入服务器逐位比较",
        locker=locker,
        mode="plain",
        candidate=code_norm,
        latency_ms=session.latency_ms,
        matched_prefix=matched_prefix,
        decision="通过" if ok else "拒绝",
    )
    return session


def run_timing_side_channel(locker: str, zero_trust_enabled: bool) -> Dict[str, object]:
    """执行时间侧信道对照实验。

    普通外卖柜把明文取件码交给服务器逐位比较，攻击者能把每个候选输入和响应时长
    记录下来，按“耗时最长的候选位”逐步恢复取件码。零知识功能外卖柜不提供这种
    明文逐位比较接口，攻击请求在承诺阶段前就被阻断，只能看到固定耗时样本。
    """

    expected = st.session_state.pickup_codes[locker]
    samples: List[Dict[str, object]] = []

    if zero_trust_enabled:
        probe_candidates = [
            "000000",
            "100000",
            "200000",
            "280000",
            "284000",
            "284900",
            "284910",
            expected,
        ]
        for attempt, candidate in enumerate(probe_candidates, start=1):
            measured = measure_zero_trust_probe(candidate)
            point = {
                "sample": len(st.session_state.latency_points) + 1,
                "latency_ms": measured["avg_latency_ms"],
                "avg_latency_ms": measured["avg_latency_ms"],
                "min_latency_ms": measured["min_latency_ms"],
                "max_latency_ms": measured["max_latency_ms"],
                "stddev_ms": measured["stddev_ms"],
                "matched_prefix": 0,
                "mode": "constant_time",
                "candidate": candidate,
                "jitter_ms": 0.0,
                "accepted": False,
                "attempt": attempt,
                "measurements": TIMING_REPEATS,
                "blocked_at": "no_plain_compare_api",
                "blocked_reason": "零知识柜不提供明文逐位比较接口",
            }
            st.session_state.latency_points.append(point)
            samples.append(point)
            push_trace(
                "时延探测",
                "攻击者提交候选明文码，请求类型检查通过网络层但未进入取件码比较",
                locker=locker,
                mode="zero_trust",
                attempt=attempt,
                candidate=candidate,
                avg_latency_ms=point["avg_latency_ms"],
                measurements=TIMING_REPEATS,
                check="parse_packet",
                result="PASS",
                stage_passed="请求格式已解析",
                decision="继续预检",
            )
            push_trace(
                "时延探测",
                "服务端要求 ZKP 承诺 X/c/s，明文候选码没有对应证明材料",
                locker=locker,
                mode="zero_trust",
                attempt=attempt,
                candidate=candidate,
                check="no_plain_compare_api",
                result="FAIL",
                blocked_at="no_plain_compare_api",
                blocked_reason="未开放逐位比较接口，无法观察匹配前缀",
                decision="拦截",
            )

        reason = "零知识模式不暴露逐位比较接口，爆破在明文比较入口前被阻断"
        mark_locker(locker, SELF_LOCKED)
        record_request(
            locker=locker,
            event_type="timing_side_channel",
            accepted=False,
            reason=reason,
            attack=True,
            latency_ms=float(samples[-1]["latency_ms"]),
            risk_delta=18,
        )
        st.session_state.attack_history.appendleft(
            {"ts": now_ts(), "locker": locker, "type": "timing_side_channel", "blocked": True}
        )
        push_log(
            "error",
            "时间侧信道爆破被零知识模式阻断",
            reason,
            locker=locker,
            samples=len(samples),
            mode="zero_trust",
            blocked_at="no_plain_compare_api",
            last_latency_ms=samples[-1]["latency_ms"],
            measurements=TIMING_REPEATS,
            decision="BLOCK",
        )
        st.session_state.last_timing_summary = {
            "locker": locker,
            "mode": "zero_trust",
            "blocked": True,
            "blocked_at": "no_plain_compare_api",
            "attack_samples": samples[-8:],
            "reference_samples": [
                {
                    "candidate": "不接收明文候选码",
                    "avg_latency_ms": 10.0,
                    "matched_prefix": "不可见",
                    "check": "no_plain_compare_api",
                    "result": "FAIL",
                    "reason": "必须提交 ZKP 承诺 X、挑战响应 s 和 nonce",
                },
                {
                    "candidate": "正确 ZKP 请求",
                    "avg_latency_ms": 10.0,
                    "matched_prefix": "不参与比较",
                    "check": "zkp_equation",
                    "result": "PASS",
                    "reason": "服务器验证等式，不做逐位明文比较",
                },
            ],
        }
        return {
            "samples": samples,
            "reason": reason,
            "recovered_code": "",
            "blocked": True,
            "blocked_at": "no_plain_compare_api",
        }

    recovered = ""
    attempt = 0
    for position in range(6):
        round_samples: List[Dict[str, object]] = []
        for digit in "0123456789":
            attempt += 1
            candidate = recovered + digit + "0" * (5 - position)
            measured = measure_plain_candidate(candidate, expected)
            point = {
                "sample": len(st.session_state.latency_points) + 1,
                "latency_ms": measured["avg_latency_ms"],
                "avg_latency_ms": measured["avg_latency_ms"],
                "min_latency_ms": measured["min_latency_ms"],
                "max_latency_ms": measured["max_latency_ms"],
                "stddev_ms": measured["stddev_ms"],
                "matched_prefix": measured["matched_prefix"],
                "mode": "early_exit",
                "candidate": candidate,
                "jitter_ms": round(max(float(measured["avg_latency_ms"]) - 2, 0), 3),
                "accepted": measured["accepted"],
                "attempt": attempt,
                "position": position + 1,
                "digit": digit,
                "measurements": TIMING_REPEATS,
            }
            st.session_state.latency_points.append(point)
            samples.append(point)
            round_samples.append(point)
            push_trace(
                "时延爆破",
                "普通柜逐位比较暴露响应时长，攻击者记录多次采样平均值",
                locker=locker,
                mode="plain",
                attempt=attempt,
                candidate=candidate,
                avg_latency_ms=point["avg_latency_ms"],
                min_latency_ms=point["min_latency_ms"],
                max_latency_ms=point["max_latency_ms"],
                measurements=TIMING_REPEATS,
                matched_prefix=point["matched_prefix"],
                decision="采样",
            )

        best = max(round_samples, key=lambda item: (float(item["avg_latency_ms"]), int(item["matched_prefix"])))
        recovered += str(best["candidate"])[position]
        push_trace(
            "时延爆破",
            f"第 {position + 1} 位选择 {recovered[-1]}：该候选平均时延最高",
            locker=locker,
            mode="plain",
            candidate=best["candidate"],
            avg_latency_ms=best["avg_latency_ms"],
            matched_prefix=best["matched_prefix"],
            recovered_code=recovered + "*" * (5 - position),
            stage_passed=f"已恢复前 {position + 1} 位",
            decision="选择该位",
        )

    final_measured = measure_plain_candidate(recovered, expected)
    final_point = {
        "sample": len(st.session_state.latency_points) + 1,
        "latency_ms": final_measured["avg_latency_ms"],
        "avg_latency_ms": final_measured["avg_latency_ms"],
        "min_latency_ms": final_measured["min_latency_ms"],
        "max_latency_ms": final_measured["max_latency_ms"],
        "stddev_ms": final_measured["stddev_ms"],
        "matched_prefix": final_measured["matched_prefix"],
        "mode": "early_exit",
        "candidate": recovered,
        "jitter_ms": round(max(float(final_measured["avg_latency_ms"]) - 2, 0), 3),
        "accepted": final_measured["accepted"],
        "attempt": attempt + 1,
        "measurements": TIMING_REPEATS,
    }
    st.session_state.latency_points.append(final_point)
    samples.append(final_point)
    final_ok = bool(final_measured["accepted"])
    push_trace(
        "时延爆破成功",
        "普通柜取件码已由耗时差逐位恢复",
        locker=locker,
        mode="plain",
        candidate=recovered,
        avg_latency_ms=final_point["avg_latency_ms"],
        measurements=TIMING_REPEATS,
        matched_prefix=final_point["matched_prefix"],
        recovered_code=recovered,
        check="plaintext_compare",
        result="PASS" if final_ok else "FAIL",
        decision="可异常开柜" if final_ok else "继续探测",
    )

    mark_locker(locker, UNLOCKED if final_ok else SELF_LOCKED)
    reason = "普通柜逐位比较，攻击者已根据时延恢复取件码"
    record_request(
        locker=locker,
        event_type="timing_side_channel",
        accepted=bool(final_ok),
        reason=reason,
        attack=True,
        latency_ms=float(final_point["latency_ms"]),
        risk_delta=42,
    )
    st.session_state.attack_history.appendleft(
        {"ts": now_ts(), "locker": locker, "type": "timing_side_channel", "blocked": False}
    )
    push_log(
        "warn",
        "普通柜时间侧信道爆破成功",
        reason,
        locker=locker,
        samples=len(samples),
        mode="plain",
        recovered_code=recovered,
        last_latency_ms=final_point["latency_ms"],
        decision="WARN",
    )
    constant_reference = []
    for candidate in [
        "000000",
        recovered[:1] + "00000",
        recovered[:2] + "0000",
        recovered[:3] + "000",
        recovered,
    ]:
        constant_reference.append(
            {
                "candidate": candidate,
                "avg_latency_ms": 10.0,
                "matched_prefix": "隐藏",
                "mode": "constant_time",
                "check": "no_plain_compare_api",
                "result": "PASS",
                "reason": "安全柜不会让正确前缀改变响应时长",
            }
        )
    st.session_state.last_timing_summary = {
        "locker": locker,
        "mode": "plain",
        "blocked": False,
        "blocked_at": "",
        "recovered_code": recovered,
        "attack_samples": samples[-18:],
        "reference_samples": constant_reference,
    }
    return {"samples": samples, "reason": reason, "recovered_code": recovered, "blocked": False}


def build_firmware_packet(payload: bytes, *, canary: bytes = CANARY_BYTES, corrupt_crc: bool = False) -> bytes:
    declared = len(payload).to_bytes(2, "big")
    header = FIRMWARE_MAGIC + bytes([FIRMWARE_VERSION]) + declared
    body = header + payload + canary
    crc = hashlib.sha256(body).digest()[:4]
    if corrupt_crc:
        crc = b"\x00\x00\x00\x00"
    return body + crc


def firmware_packet_preview(raw: bytes, declared_len: int) -> Dict[str, object]:
    declared_len_offset = len(FIRMWARE_MAGIC) + 1
    payload_start = declared_len_offset + 2
    payload_end = min(payload_start + declared_len, len(raw))
    payload = raw[payload_start:payload_end]
    canary_start = payload_start + declared_len
    canary_end = min(canary_start + len(CANARY_BYTES), len(raw))
    canary_seen = raw[canary_start:canary_end]
    crc_seen = raw[canary_end: min(canary_end + 4, len(raw))]
    return {
        "raw_len": len(raw),
        "payload_len": len(payload),
        "payload_preview": payload[:30].decode("utf-8", errors="replace"),
        "payload_hex": payload[:20].hex(),
        "canary_seen": canary_seen.hex() if canary_seen else "missing",
        "crc": crc_seen.hex() if crc_seen else "missing",
    }


def firmware_check_rows(raw: bytes, declared_len: int, *, secure_mode: bool) -> List[Dict[str, object]]:
    """生成固件解析检查步骤表。

    这个函数只做可视化拆解，不替代真正的 parse_firmware_packet。它把安全解析器里
    隐含的判定拆成课堂上能看懂的五步：magic、版本、长度、金丝雀、CRC。普通柜模式下
    会明确标注哪些检查被跳过；零知识/安全模式下会标出准确失败点。
    """

    rows: List[Dict[str, object]] = []
    declared_len_offset = len(FIRMWARE_MAGIC) + 1
    payload_start = declared_len_offset + 2
    payload_end = payload_start + declared_len
    canary_end = payload_end + len(CANARY_BYTES)
    crc_end = canary_end + 4

    def add(check: str, result: str, detail: str, blocked_at: str = "") -> None:
        rows.append(
            {
                "步骤": len(rows) + 1,
                "check": check,
                "result": result,
                "detail": detail,
                "blocked_at": blocked_at,
            }
        )

    if len(raw) < len(FIRMWARE_MAGIC):
        add("magic_check", "FAIL", "报文太短，无法读取 magic", "magic_check")
        return rows
    add(
        "magic_check",
        "PASS" if raw[: len(FIRMWARE_MAGIC)] == FIRMWARE_MAGIC else "FAIL",
        "检查报文是否来自 Aegis 固件通道",
        "" if raw[: len(FIRMWARE_MAGIC)] == FIRMWARE_MAGIC else "magic_check",
    )
    if rows[-1]["result"] == "FAIL":
        return rows

    version = raw[len(FIRMWARE_MAGIC)] if len(raw) > len(FIRMWARE_MAGIC) else -1
    add(
        "version_check",
        "PASS" if version == FIRMWARE_VERSION else "FAIL",
        f"检查固件协议版本 version={version}",
        "" if version == FIRMWARE_VERSION else "version_check",
    )
    if rows[-1]["result"] == "FAIL":
        return rows

    if secure_mode:
        if len(raw) < crc_end:
            add("length_check", "FAIL", "声明长度超过实际报文长度，疑似越界读", "length_check")
            return rows
        if declared_len > MAX_FIRMWARE_PAYLOAD:
            add(
                "length_check",
                "FAIL",
                f"payload 长度 {declared_len} 超过安全阈值 {MAX_FIRMWARE_PAYLOAD}",
                "length_check",
            )
            # 继续展示 canary 是否已经被破坏，便于解释攻击影响。
        else:
            add("length_check", "PASS", f"payload 长度 {declared_len} 未超过安全阈值")
    else:
        add("length_check", "SKIP", "普通柜旧式解析器未检查 payload 长度")

    canary = raw[payload_end:canary_end] if len(raw) >= canary_end else b""
    canary_ok = canary == CANARY_BYTES
    if secure_mode:
        add(
            "canary_check",
            "PASS" if canary_ok else "FAIL",
            "检查 payload 后方守护字节是否被覆盖",
            "" if canary_ok else "canary_check",
        )
        if not canary_ok:
            return rows
    else:
        add("canary_check", "SKIP", "普通柜未启用栈金丝雀，payload 覆盖不会立即触发自锁")

    actual_crc = raw[canary_end:crc_end] if len(raw) >= crc_end else b""
    expected_crc = hashlib.sha256(raw[:canary_end]).digest()[:4] if len(raw) >= canary_end else b""
    crc_ok = actual_crc == expected_crc and bool(actual_crc)
    if secure_mode:
        add(
            "crc_check",
            "PASS" if crc_ok else "FAIL",
            "检查 header、payload、canary 是否被静默篡改",
            "" if crc_ok else "crc_check",
        )
    else:
        add("crc_check", "SKIP", "普通柜未校验 CRC，篡改后的报文仍会继续处理")
    return rows


def reference_firmware_payload(locker: str, *, secure_mode: bool) -> Dict[str, object]:
    payload = b"PING:" + locker.encode("utf-8")
    raw = build_firmware_packet(payload, canary=CANARY_BYTES, corrupt_crc=False)
    preview = firmware_packet_preview(raw, len(payload))
    checks = firmware_check_rows(raw, len(payload), secure_mode=secure_mode)
    return {
        "名称": "正确心跳报文",
        "raw_len": preview["raw_len"],
        "payload_len": len(payload),
        "payload_preview": preview["payload_preview"],
        "payload_hex": preview["payload_hex"],
        "canary_seen": preview["canary_seen"],
        "crc": preview["crc"],
        "检查流水": " → ".join(
            f"{value_label(item['check'])}:{value_label(item['result'])}" for item in checks
        ),
        "decision": "通过",
        "blocked_at": "",
    }


def parse_firmware_packet(raw: bytes) -> FirmwarePacket:
    """解析固件报文并执行 Stack Canary 防护。

    报文结构：
        magic(7) | version(1) | payload_len(2) | payload | canary | crc(4)

    安全意义：
    - payload_len 用于显式边界检查，阻止超长字段写入固定缓冲区。
    - canary 必须紧跟 payload，若攻击 payload 覆盖栈保护区，canary 会变。
    - crc 绑定 header、payload 与 canary，防止攻击者静默篡改报文内容。
    """

    min_len = len(FIRMWARE_MAGIC) + 1 + 2 + len(CANARY_BYTES) + 4
    if len(raw) < min_len:
        raise SecurityMemoryError("固件报文结构截断，已拒绝解析")
    if raw[: len(FIRMWARE_MAGIC)] != FIRMWARE_MAGIC:
        raise SecurityMemoryError("固件报文 magic 不匹配")
    version = raw[len(FIRMWARE_MAGIC)]
    if version != FIRMWARE_VERSION:
        raise SecurityMemoryError("固件版本不受信任")

    declared_len_offset = len(FIRMWARE_MAGIC) + 1
    declared_len = int.from_bytes(raw[declared_len_offset : declared_len_offset + 2], "big")
    payload_start = declared_len_offset + 2
    payload_end = payload_start + declared_len
    canary_end = payload_end + len(CANARY_BYTES)
    crc_end = canary_end + 4
    if len(raw) < crc_end:
        raise SecurityMemoryError("声明长度超过实际报文长度，疑似越界读")

    payload = raw[payload_start:payload_end]
    canary = raw[payload_end:canary_end]
    actual_crc = raw[canary_end:crc_end]
    expected_crc = hashlib.sha256(raw[:canary_end]).digest()[:4]
    if declared_len > MAX_FIRMWARE_PAYLOAD and canary != CANARY_BYTES:
        raise SecurityMemoryError(
            f"载荷长度={declared_len} 超过阈值且栈金丝雀已损坏"
        )
    if canary != CANARY_BYTES:
        raise SecurityMemoryError("栈金丝雀不匹配，疑似内存破坏")
    if actual_crc != expected_crc:
        raise SecurityMemoryError("固件报文 CRC 校验失败")
    if declared_len > MAX_FIRMWARE_PAYLOAD:
        raise SecurityMemoryError(f"载荷长度={declared_len} 超过固件安全阈值")

    return FirmwarePacket(
        version=version,
        declared_len=declared_len,
        payload_len=len(payload),
        payload_sha256_short=hashlib.sha256(payload).hexdigest()[:12],
        crc_short=actual_crc.hex(),
    )


def add_replay_step(
    steps: List[Dict[str, object]],
    *,
    check: str,
    result: str,
    detail: str,
    blocked_at: str = "",
    **fields: object,
) -> None:
    row = {
        "序号": len(steps) + 1,
        "check": check,
        "result": result,
        "detail": detail,
        "blocked_at": blocked_at,
    }
    row.update(fields)
    steps.append(row)


def replay_packet_digest(packet: Dict[str, object], zero_trust_enabled: bool) -> str:
    if zero_trust_enabled:
        return transcript_id(
            str(packet.get("locker", "")),
            int(packet.get("X", 0)),
            int(packet.get("c", 0)),
            int(packet.get("s", 0)),
            str(packet.get("nonce", "")),
        )
    return plain_packet_id(
        str(packet.get("locker", "")),
        str(packet.get("pickup_code", "")),
        str(packet.get("nonce", "")),
        float(packet.get("timestamp", 0.0)),
    )


def verify_replay_packet(
    packet: Dict[str, object],
    target_locker: str,
    *,
    zero_trust_enabled: bool,
    simulated_age: float = SIMULATED_REPLAY_AGE_SECONDS,
) -> Dict[str, object]:
    """按服务器视角验证一条历史重放报文。

    这里故意把每个判定点拆开显示，避免“按钮一点就成功/失败”的黑箱演示：
    1. 先解析报文，确认能读出格口、设备编号和摘要。
    2. 再做设备编号绑定与格口绑定，防止 A1 报文被拿去打开 A4。
    3. 校验摘要是否与报文字段一致，防止攻击者改 locker 或 device_id。
    4. 零知识柜继续检查时间窗口和摘要缓存；普通柜为了对照，明确标出这些保护缺失。
    5. 最后才进入明文取件码或 ZKP 等式校验。
    """

    steps: List[Dict[str, object]] = []
    source_locker = str(packet.get("locker", ""))
    source_device_id = str(packet.get("device_id", ""))
    target_device_id = device_id_for(target_locker)
    packet_digest = str(packet.get("digest", ""))
    mode = "zero_trust" if zero_trust_enabled else "plain"

    def fail(blocked_at: str, reason: str) -> Dict[str, object]:
        st.session_state.last_replay_steps = steps
        return {
            "accepted": False,
            "blocked": True,
            "blocked_at": blocked_at,
            "reason": reason,
            "steps": steps,
            "source_locker": source_locker,
            "target_locker": target_locker,
            "source_device_id": source_device_id,
            "target_device_id": target_device_id,
        }

    add_replay_step(
        steps,
        check="parse_packet",
        result="PASS",
        detail="报文结构可解析，进入服务器绑定校验",
        source_locker=source_locker,
        target_locker=target_locker,
        source_device_id=source_device_id,
        target_device_id=target_device_id,
        digest=short_hex(packet_digest),
    )

    if source_device_id != target_device_id:
        add_replay_step(
            steps,
            check="device_binding",
            result="FAIL",
            detail="报文设备编号与当前目标格口登记设备不一致",
            blocked_at="device_binding",
            source_device_id=source_device_id,
            target_device_id=target_device_id,
        )
        return fail("device_binding", "replay device binding rejected")
    add_replay_step(
        steps,
        check="device_binding",
        result="PASS",
        detail="设备编号与目标格口匹配",
        source_device_id=source_device_id,
        target_device_id=target_device_id,
    )

    if source_locker != target_locker:
        add_replay_step(
            steps,
            check="locker_binding",
            result="FAIL",
            detail="报文声明格口与攻击目标格口不一致",
            blocked_at="locker_binding",
            source_locker=source_locker,
            target_locker=target_locker,
        )
        return fail("locker_binding", "replay locker binding rejected")
    add_replay_step(
        steps,
        check="locker_binding",
        result="PASS",
        detail="报文格口与目标格口一致",
        source_locker=source_locker,
        target_locker=target_locker,
    )

    try:
        expected_digest = replay_packet_digest(packet, zero_trust_enabled)
    except (TypeError, ValueError):
        expected_digest = ""
    if not hmac.compare_digest(packet_digest, expected_digest):
        add_replay_step(
            steps,
            check="digest_mismatch",
            result="FAIL",
            detail="报文摘要与字段重新计算结果不一致，疑似篡改",
            blocked_at="digest_mismatch",
            digest=short_hex(packet_digest),
        )
        return fail("digest_mismatch", "replay digest mismatch")
    add_replay_step(
        steps,
        check="digest_mismatch",
        result="PASS",
        detail="摘要绑定 device_id、格口、nonce 与认证字段，未发现篡改",
        digest=short_hex(packet_digest),
    )

    if zero_trust_enabled:
        if simulated_age > REPLAY_WINDOW_SECONDS:
            add_replay_step(
                steps,
                check="timestamp_window",
                result="FAIL",
                detail="历史报文超过 30 秒有效窗口，不能作为新请求使用",
                blocked_at="timestamp_window",
                simulated_age_seconds=simulated_age,
                window_seconds=REPLAY_WINDOW_SECONDS,
            )
            return fail("timestamp_window", "replay timestamp expired")
        add_replay_step(
            steps,
            check="timestamp_window",
            result="PASS",
            detail="报文仍处于允许时间窗内",
            simulated_age_seconds=simulated_age,
            window_seconds=REPLAY_WINDOW_SECONDS,
        )

        if packet_digest in st.session_state.used_transcripts:
            add_replay_step(
                steps,
                check="digest_cache",
                result="FAIL",
                detail="该认证摘要已经使用过，不能再次开柜",
                blocked_at="digest_cache",
                digest=short_hex(packet_digest),
            )
            return fail("digest_cache", "replay digest reused")
        add_replay_step(
            steps,
            check="digest_cache",
            result="PASS",
            detail="摘要缓存未命中，继续做 ZKP 等式校验",
            digest=short_hex(packet_digest),
        )

        expected_code = st.session_state.pickup_codes[target_locker]
        x_expected, _ = derive_private_x(target_locker, expected_code)
        public_y_expected = zkp_public_key(x_expected)
        proof_ok, left, right = zkp_verify(
            public_y_expected,
            int(packet.get("X", 0)),
            int(packet.get("c", 0)),
            int(packet.get("s", 0)),
        )
        add_replay_step(
            steps,
            check="zkp_equation",
            result="PASS" if proof_ok else "FAIL",
            detail="服务器复算 g^s 与 X*y^c 是否相等",
            left=left,
            right=right,
            public_y=public_y_expected,
        )
        st.session_state.last_replay_steps = steps
        return {
            "accepted": proof_ok,
            "blocked": not proof_ok,
            "blocked_at": "" if proof_ok else "zkp_equation",
            "reason": "replay accepted" if proof_ok else "replay zkp equation mismatch",
            "steps": steps,
            "source_locker": source_locker,
            "target_locker": target_locker,
            "source_device_id": source_device_id,
            "target_device_id": target_device_id,
        }

    add_replay_step(
        steps,
        check="timestamp_window",
        result="SKIP",
        detail="普通柜缺少时间窗口校验，同柜旧报文不会因为过期被拒绝",
        simulated_age_seconds=simulated_age,
        window_seconds=REPLAY_WINDOW_SECONDS,
    )
    add_replay_step(
        steps,
        check="digest_cache",
        result="SKIP",
        detail="普通柜缺少摘要缓存，同一 nonce 或摘要可被重复提交",
        digest=short_hex(packet_digest),
    )
    expected_code = st.session_state.pickup_codes[target_locker]
    code_ok = hmac.compare_digest(str(packet.get("pickup_code", "")), expected_code)
    add_replay_step(
        steps,
        check="plaintext_compare",
        result="PASS" if code_ok else "FAIL",
        detail="普通柜最终只比较报文中的明文取件码",
        pickup_code=packet.get("pickup_code", ""),
        matched_prefix=6 if code_ok else 0,
    )
    st.session_state.last_replay_steps = steps
    return {
        "accepted": code_ok,
        "blocked": not code_ok,
        "blocked_at": "" if code_ok else "plaintext_compare",
        "reason": "plain replay accepted" if code_ok else "plain replay code rejected",
        "steps": steps,
        "source_locker": source_locker,
        "target_locker": target_locker,
        "source_device_id": source_device_id,
        "target_device_id": target_device_id,
    }


def compare_dicts(left: Dict[str, object], right: Dict[str, object], keys: List[str]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for key in keys:
        left_value = left.get(key, "")
        right_value = right.get(key, "")
        same = str(left_value) == str(right_value)
        rows.append(
            {
                "字段": field_label(key),
                "攻击样本": str(left_value),
                "正确样本": str(right_value),
                "是否一致": "一致" if same else "不一致",
            }
        )
    return rows


def replay_difference_rows(
    attack_packet: Dict[str, object],
    reference_packet: Dict[str, object],
    zero_trust_enabled: bool,
) -> List[Dict[str, object]]:
    keys = (
        ["device_id", "locker", "public_y", "X", "c", "s", "nonce", "timestamp", "digest"]
        if zero_trust_enabled
        else ["device_id", "locker", "pickup_code", "nonce", "timestamp", "digest"]
    )
    return compare_dicts(attack_packet, reference_packet, keys)


def simulate_replay_attack(locker: str, zero_trust_enabled: bool) -> Dict[str, object]:
    if zero_trust_enabled:
        packet: Optional[Dict[str, object]] = st.session_state.last_zkp_replay_packet
        if packet is None:
            session = perform_zkp_unlock(locker, st.session_state.pickup_codes[locker])
            packet = zkp_session_packet(session)
            st.session_state.last_zkp_replay_packet = packet
            push_trace(
                "准备历史报文",
                "生成一条可重放的零知识认证记录",
                locker=locker,
                mode="zero_trust",
                X=session.commitment_x,
                c=session.challenge_c,
                s=session.response_s,
                nonce=session.nonce,
                decision="历史样本已生成",
            )

        st.session_state.last_replay_packet = packet
        verdict = verify_replay_packet(packet, locker, zero_trust_enabled=True)
        st.session_state.last_replay_target_locker = locker
        st.session_state.last_replay_mode = "zero_trust"
        st.session_state.last_replay_verdict = verdict
        blocked = bool(verdict["blocked"])
        blocked_at = str(verdict.get("blocked_at", ""))
        mark_locker(locker, SELF_LOCKED if blocked else UNLOCKED)
        record_request(
            locker=locker,
            event_type="replay_attack",
            accepted=not blocked,
            reason=str(verdict["reason"]),
            attack=True,
            risk_delta=28,
        )
        st.session_state.attack_history.appendleft(
            {"ts": now_ts(), "locker": locker, "type": "replay_attack", "blocked": blocked}
        )
        push_trace(
            "重放报文",
            "攻击者原样重放零知识认证记录",
            locker=locker,
            mode="zero_trust",
            source_locker=verdict["source_locker"],
            target_locker=locker,
            source_device_id=verdict["source_device_id"],
            target_device_id=verdict["target_device_id"],
            X=packet.get("X"),
            c=packet.get("c"),
            s=packet.get("s"),
            nonce=packet.get("nonce"),
            timestamp=packet.get("timestamp"),
            simulated_age_seconds=SIMULATED_REPLAY_AGE_SECONDS,
            blocked_at=blocked_at,
            decision="拦截" if blocked else "通过",
        )
        push_log(
            "error" if blocked else "warn",
            "历史报文重放攻击被拦截" if blocked else "零知识重放异常通过",
            "服务器逐步检查设备绑定、格口绑定、时间窗、摘要缓存与 ZKP 等式，已明确定位阻断点。",
            locker=locker,
            mode="zero_trust",
            source_locker=verdict["source_locker"],
            target_locker=locker,
            source_device_id=verdict["source_device_id"],
            target_device_id=verdict["target_device_id"],
            transcript=short_hex(str(packet.get("digest", ""))),
            blocked_at=blocked_at,
            decision="BLOCK" if blocked else "WARN",
        )
        return {
            "blocked": blocked,
            "reason": str(verdict["reason"]),
            "packet": packet,
            "blocked_at": blocked_at,
            "steps": verdict["steps"],
        }

    packet: Optional[Dict[str, object]] = st.session_state.last_plain_replay_packet
    if packet is None:
        code = st.session_state.pickup_codes[locker]
        session = handle_plain_pickup(locker, code)
        packet = plain_session_packet(session)
        st.session_state.last_plain_replay_packet = packet
    st.session_state.last_replay_packet = packet
    verdict = verify_replay_packet(packet, locker, zero_trust_enabled=False)
    st.session_state.last_replay_target_locker = locker
    st.session_state.last_replay_mode = "plain"
    st.session_state.last_replay_verdict = verdict
    blocked = bool(verdict["blocked"])
    mark_locker(locker, SELF_LOCKED if blocked else UNLOCKED)
    record_request(
        locker=locker,
        event_type="replay_attack",
        accepted=not blocked,
        reason=str(verdict["reason"]),
        attack=True,
        latency_ms=float(packet.get("latency_ms", 0.0)),
        risk_delta=20 if blocked else 45,
    )
    st.session_state.attack_history.appendleft(
        {"ts": now_ts(), "locker": locker, "type": "replay_attack", "blocked": blocked}
    )
    push_trace(
        "重放报文",
        "普通柜重放验证：同柜旧报文会通过，跨柜旧报文会被设备/格口绑定拦截",
        locker=locker,
        mode="plain",
        source_locker=verdict["source_locker"],
        target_locker=locker,
        source_device_id=verdict["source_device_id"],
        target_device_id=verdict["target_device_id"],
        device_id=packet.get("device_id"),
        pickup_code=packet.get("pickup_code"),
        nonce=packet.get("nonce"),
        timestamp=packet.get("timestamp"),
        blocked_at=verdict.get("blocked_at", ""),
        decision="拦截" if blocked else "通过",
    )
    push_log(
        "error" if blocked else "warn",
        "普通柜跨柜重放被绑定校验拦截" if blocked else "普通柜同柜重放攻击成功",
        "普通柜仍然缺少时间窗口和摘要缓存：同柜旧报文会成功；但设备编号和格口不匹配时不会跨柜开锁。",
        locker=locker,
        mode="plain",
        source_locker=verdict["source_locker"],
        target_locker=locker,
        source_device_id=verdict["source_device_id"],
        target_device_id=verdict["target_device_id"],
        device_id=packet.get("device_id"),
        pickup_code=packet.get("pickup_code"),
        nonce=packet.get("nonce"),
        transcript=short_hex(str(packet["digest"])),
        blocked_at=verdict.get("blocked_at", ""),
        decision="BLOCK" if blocked else "WARN",
    )
    return {
        "blocked": blocked,
        "reason": str(verdict["reason"]),
        "packet": packet,
        "blocked_at": str(verdict.get("blocked_at", "")),
        "steps": verdict["steps"],
    }


def simulate_overflow_attack(locker: str, zero_trust_enabled: bool) -> Dict[str, object]:
    payload_cases = [
        ("正常心跳", b"PING:" + locker.encode("utf-8")),
        ("边界载荷", b"A" * MAX_FIRMWARE_PAYLOAD),
        ("越界填充", b"A" * 96 + b"|LOCK_STATE=OPEN|"),
        ("返回地址覆盖", b"A" * 112 + b"RET_OVERWRITE"),
    ]
    rows: List[Dict[str, object]] = []
    blocked = False
    reason = "plain overflow unsafe parse"
    blocked_at = ""

    for attempt, (name, payload) in enumerate(payload_cases, start=1):
        corrupt = len(payload) > MAX_FIRMWARE_PAYLOAD
        raw = build_firmware_packet(
            payload,
            canary=b"CORRUPTED_CANARY" if corrupt else CANARY_BYTES,
            corrupt_crc=corrupt,
        )
        preview = firmware_packet_preview(raw, len(payload))
        check_rows = firmware_check_rows(raw, len(payload), secure_mode=zero_trust_enabled)
        first_failed = next((item for item in check_rows if item["result"] == "FAIL"), None)
        row = {
            "attempt": attempt,
            "名称": name,
            "raw_len": preview["raw_len"],
            "payload_len": len(payload),
            "payload_preview": preview["payload_preview"],
            "payload_hex": preview["payload_hex"],
            "canary_seen": preview["canary_seen"],
            "crc": preview["crc"],
            "检查流水": " → ".join(
                f"{value_label(item['check'])}:{value_label(item['result'])}" for item in check_rows
            ),
            "decision": "待解析",
            "blocked_at": "",
        }

        if zero_trust_enabled:
            try:
                parse_firmware_packet(raw)
                row["decision"] = "通过"
            except SecurityMemoryError as exc:
                blocked = True
                reason = str(exc)
                blocked_at = str(first_failed["blocked_at"]) if first_failed else (
                    "canary_check" if "金丝雀" in reason or "Canary" in reason else "length_check"
                )
                row["decision"] = "拦截"
                row["blocked_at"] = blocked_at
            for check_row in check_rows:
                push_trace(
                    "固件载荷检查",
                    f"{name}：{check_row['detail']}",
                    locker=locker,
                    mode="zero_trust",
                    attempt=attempt,
                    payload_len=len(payload),
                    payload_preview=preview["payload_preview"],
                    payload_hex=preview["payload_hex"],
                    check=check_row["check"],
                    result=check_row["result"],
                    blocked_at=check_row["blocked_at"] or "",
                    decision="继续" if check_row["result"] == "PASS" else value_label(check_row["result"]),
                )
            push_trace(
                "固件载荷",
                f"{name}：{row['decision']}",
                locker=locker,
                mode="zero_trust",
                attempt=attempt,
                payload_len=len(payload),
                payload_preview=preview["payload_preview"],
                payload_hex=preview["payload_hex"],
                canary_seen=preview["canary_seen"],
                blocked_at=row["blocked_at"] or "未触发",
                decision=row["decision"],
            )
            if blocked:
                rows.append(row)
                break
        else:
            # 普通柜演示缺少长度、CRC、canary 三重检查。这里不调用安全解析器，
            # 用“危险解析通过”模拟旧式固件直接把 payload 写入固定缓冲区。
            row["decision"] = "危险解析通过" if len(payload) > MAX_FIRMWARE_PAYLOAD else "通过"
            for check_row in check_rows:
                push_trace(
                    "固件载荷检查",
                    f"{name}：{check_row['detail']}",
                    locker=locker,
                    mode="plain",
                    attempt=attempt,
                    payload_len=len(payload),
                    payload_preview=preview["payload_preview"],
                    payload_hex=preview["payload_hex"],
                    check=check_row["check"],
                    result=check_row["result"],
                    decision="缺失防护" if check_row["result"] == "SKIP" else "继续",
                )
            push_trace(
                "固件载荷",
                f"{name}：普通柜未检查边界",
                locker=locker,
                mode="plain",
                attempt=attempt,
                payload_len=len(payload),
                payload_preview=preview["payload_preview"],
                payload_hex=preview["payload_hex"],
                canary_seen=preview["canary_seen"],
                decision=row["decision"],
            )
        rows.append(row)

    st.session_state.last_payload_rows = rows
    st.session_state.last_overflow_locker = locker
    st.session_state.last_overflow_mode = "zero_trust" if zero_trust_enabled else "plain"
    if zero_trust_enabled:
        mark_locker(locker, SELF_LOCKED)
        record_request(
            locker=locker,
            event_type="firmware_overflow",
            accepted=False,
            reason=reason,
            attack=True,
            risk_delta=35,
        )
        level = "error"
        title = "恶意溢出载荷注入被拦截"
        message = reason
        decision = "BLOCK"
    else:
        mark_locker(locker, UNLOCKED)
        record_request(
            locker=locker,
            event_type="firmware_overflow",
            accepted=True,
            reason="plain overflow unsafe parse",
            attack=True,
            risk_delta=48,
        )
        level = "warn"
        title = "普通柜固件溢出载荷造成危险解析"
        message = "普通柜解析器缺少长度、CRC 和 canary 检查，越界 payload 被继续处理。"
        decision = "WARN"

    st.session_state.attack_history.appendleft(
        {"ts": now_ts(), "locker": locker, "type": "firmware_overflow", "blocked": zero_trust_enabled}
    )
    last_row = rows[-1] if rows else {}
    push_log(
        level,
        title,
        message,
        locker=locker,
        mode="zero_trust" if zero_trust_enabled else "plain",
        raw_len=last_row.get("raw_len", ""),
        payload_len=last_row.get("payload_len", ""),
        payload_preview=last_row.get("payload_preview", ""),
        canary_seen=last_row.get("canary_seen", ""),
        blocked_at=blocked_at,
        decision=decision,
    )
    return {
        "blocked": zero_trust_enabled,
        "reason": reason if zero_trust_enabled else "plain overflow unsafe parse",
        "rows": rows,
        "blocked_at": blocked_at,
    }


def handle_normal_pickup(locker: str, code: str, secure_mode: bool) -> ZKPSession:
    code_norm = normalize_code(code)
    expected = st.session_state.pickup_codes[locker]
    compare_ok, latency_ms, matched_prefix = secure_pickup_compare(
        code_norm,
        expected,
        insecure_mode=not secure_mode,
    )
    st.session_state.latency_points.append(
        {
            "sample": len(st.session_state.latency_points) + 1,
            "latency_ms": round(latency_ms, 3),
            "matched_prefix": matched_prefix,
            "mode": "constant_time" if secure_mode else "early_exit",
            "candidate": code_norm,
            "jitter_ms": 0 if secure_mode else round(max(latency_ms - 2, 0), 3),
            "accepted": compare_ok,
        }
    )
    session = perform_zkp_unlock(locker, code_norm)
    if session.accepted and compare_ok:
        mark_locker(locker, UNLOCKED)
        record_request(
            locker=locker,
            event_type="zkp_unlock",
            accepted=True,
            reason="ZKP proof accepted",
            attack=False,
            latency_ms=latency_ms,
            risk_delta=-8,
        )
        push_log(
            "success",
            "ZKP 零知识取件验证成功",
            "服务器未接收明文取件码，仅通过 Schnorr 等式确认用户知道秘密。",
            locker=locker,
            X=session.commitment_x,
            c=session.challenge_c,
            s=session.response_s,
            left=session.left_value,
            right=session.right_value,
            public_y=session.public_y,
        )
    else:
        mark_locker(locker, LOCKED)
        record_request(
            locker=locker,
            event_type="zkp_unlock",
            accepted=False,
            reason=session.reason,
            attack=False,
            latency_ms=latency_ms,
            risk_delta=8,
        )
        push_log(
            "warn",
            "ZKP 零知识验证失败",
            "响应 s 无法满足 g^s == X*y^c，格口保持锁定。",
            locker=locker,
            X=session.commitment_x,
            c=session.challenge_c,
            s=session.response_s,
            left=session.left_value,
            right=session.right_value,
            reason=session.reason,
        )
    return session


def inject_css() -> None:
    st.markdown(
        """
        <style>
        :root {
            --bg: #030507;
            --panel: rgba(11, 17, 23, 0.94);
            --panel-2: rgba(4, 10, 17, 0.92);
            --line: rgba(31, 230, 255, 0.34);
            --line-weak: rgba(96, 165, 250, 0.18);
            --cyan: #1FE6FF;
            --green: #2DFF9A;
            --amber: #FFB020;
            --red: #FF3B4F;
            --text: #E6F7FF;
            --muted: #8AA4B8;
        }

        * { box-sizing: border-box; }

        .stApp {
            color: var(--text);
            background:
                radial-gradient(circle at 18% 8%, rgba(31, 230, 255, 0.13), transparent 25%),
                radial-gradient(circle at 84% 16%, rgba(255, 176, 32, 0.07), transparent 22%),
                radial-gradient(circle at 82% 82%, rgba(255, 59, 79, 0.08), transparent 25%),
                linear-gradient(rgba(31, 230, 255, 0.035) 1px, transparent 1px),
                linear-gradient(90deg, rgba(31, 230, 255, 0.035) 1px, transparent 1px),
                #030507;
            background-size: auto, auto, 28px 28px, 28px 28px, auto;
        }

        .block-container {
            padding-top: 0.78rem;
            padding-bottom: 2rem;
            max-width: 1500px;
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, rgba(3, 5, 7, 0.98), rgba(8, 13, 19, 0.98));
            border-right: 1px solid rgba(31, 230, 255, 0.22);
        }

        [data-testid="stHeader"],
        [data-testid="stToolbar"],
        [data-testid="stDecoration"],
        #MainMenu,
        footer {
            display: none !important;
        }

        [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
            gap: 0.66rem;
        }

        [data-testid="stSidebar"] [data-testid="stSidebarContent"] {
            overflow-y: hidden;
            padding-top: 0.8rem;
            padding-bottom: 0.6rem;
        }

        [data-testid="stSidebar"] h2,
        [data-testid="stSidebar"] h3 {
            margin: 0.08rem 0 0.24rem 0;
        }

        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] label {
            margin-bottom: 0.1rem;
        }

        [data-testid="stSidebar"] .stAlert {
            padding: 0.42rem 0.55rem;
        }

        [data-testid="stSidebar"] hr {
            margin: 0.48rem 0;
        }

        .touch-console {
            position: relative;
            border: 1px solid rgba(31, 230, 255, 0.28);
            border-radius: 16px;
            padding: 0.7rem 0.76rem;
            background:
                linear-gradient(135deg, rgba(31, 230, 255, 0.10), rgba(4, 10, 17, 0.88)),
                rgba(4, 10, 17, 0.92);
            overflow: hidden;
            box-shadow: inset 0 0 24px rgba(31, 230, 255, 0.06), 0 0 26px rgba(0, 0, 0, 0.28);
        }

        .touch-console::before,
        .hero::before,
        .panel::before {
            content: "";
            position: absolute;
            inset: 0;
            padding: 1px;
            border-radius: inherit;
            background: linear-gradient(120deg, rgba(31,230,255,0.70), transparent 30%, rgba(45,255,154,0.46) 52%, transparent 70%, rgba(255,176,32,0.62));
            background-size: 220% 220%;
            animation: borderBeam 6s linear infinite;
            -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            pointer-events: none;
        }

        .console-kicker {
            font-size: 0.72rem;
            color: var(--cyan);
            font-weight: 900;
            letter-spacing: 0.04em;
        }

        .console-title {
            margin-top: 0.1rem;
            font-size: 1.08rem;
            font-weight: 950;
            color: #F6FDFF;
        }

        .console-subtitle {
            color: var(--muted);
            font-size: 0.72rem;
            line-height: 1.35;
            margin-top: 0.2rem;
        }

        .console-code {
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.4rem;
            border-radius: 12px;
            min-height: 38px;
            padding: 0.42rem 0.55rem;
            background: rgba(45, 255, 154, 0.08);
            border: 1px solid rgba(45, 255, 154, 0.24);
            color: #D9FFE9;
            font-size: 0.78rem;
            font-weight: 850;
        }

        .console-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.5rem;
            margin-top: 0;
        }

        .console-chip {
            border: 1px solid rgba(31, 230, 255, 0.18);
            border-radius: 12px;
            padding: 0.34rem 0.42rem;
            background: rgba(2, 6, 10, 0.74);
            color: #BFEFFF;
            font-size: 0.7rem;
            line-height: 1.22;
        }

        .hero {
            position: relative;
            border: 1px solid var(--line);
            border-radius: 16px;
            padding: 0.82rem 1rem;
            background:
                linear-gradient(135deg, rgba(31, 230, 255, 0.10), rgba(3, 5, 7, 0.88) 34%, rgba(255, 59, 79, 0.08));
            box-shadow: 0 0 36px rgba(31, 230, 255, 0.10), inset 0 0 32px rgba(31, 230, 255, 0.04);
            overflow: hidden;
            margin-bottom: 0.72rem;
        }

        .hero::after, .panel::after {
            content: "";
            position: absolute;
            inset: 0;
            pointer-events: none;
            background: linear-gradient(90deg, transparent, rgba(31, 230, 255, 0.08), transparent);
            transform: translateX(-100%);
            animation: glare 6s ease-in-out infinite;
        }

        @keyframes glare {
            0%, 58% { transform: translateX(-110%); opacity: 0; }
            68% { opacity: 0.9; }
            86%, 100% { transform: translateX(110%); opacity: 0; }
        }

        @keyframes borderBeam {
            0% { background-position: 0% 50%; }
            100% { background-position: 220% 50%; }
        }

        @keyframes panelIn {
            0% { opacity: 0; transform: translateY(10px) scale(0.985); }
            100% { opacity: 1; transform: translateY(0) scale(1); }
        }

        @keyframes softPulse {
            0%, 100% { opacity: 0.78; transform: scaleX(0.86); }
            50% { opacity: 1; transform: scaleX(1); }
        }

        .hero-title {
            font-size: 1.78rem;
            font-weight: 900;
            letter-spacing: 0;
            margin: 0;
            color: #F6FDFF;
        }

        .hero-sub {
            color: var(--muted);
            margin-top: 0.35rem;
            font-size: 0.95rem;
        }

        .tag-row {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.75rem;
        }

        .tag {
            border: 1px solid rgba(31, 230, 255, 0.28);
            background: rgba(31, 230, 255, 0.08);
            color: #CFFBFF;
            border-radius: 999px;
            padding: 0.24rem 0.62rem;
            font-size: 0.75rem;
            font-weight: 800;
        }

        .tag.cn {
            border-radius: 12px;
        }

        .dashboard-band {
            display: grid;
            grid-template-columns: 1.2fr 0.8fr;
            gap: 0.7rem;
            margin-bottom: 0.72rem;
        }

        .flow-card {
            position: relative;
            border: 1px solid rgba(31, 230, 255, 0.16);
            border-radius: 16px;
            padding: 0.72rem 0.85rem;
            background: rgba(4, 10, 17, 0.82);
            overflow: hidden;
        }

        .flow-card::after {
            content: "";
            position: absolute;
            left: 0.85rem;
            right: 0.85rem;
            bottom: 0.52rem;
            height: 2px;
            transform-origin: left;
            border-radius: 999px;
            background: linear-gradient(90deg, transparent, var(--cyan), var(--green), transparent);
            animation: softPulse 2.8s ease-in-out infinite;
        }

        .flow-title {
            color: #F6FDFF;
            font-weight: 900;
            font-size: 0.86rem;
            margin-bottom: 0.28rem;
        }

        .flow-copy {
            color: var(--muted);
            font-size: 0.74rem;
            line-height: 1.45;
        }

        .panel {
            position: relative;
            border: 1px solid var(--line-weak);
            border-radius: 16px;
            padding: 0.78rem;
            background: var(--panel);
            box-shadow: inset 0 0 0 1px rgba(255,255,255,0.02), 0 0 30px rgba(0,0,0,0.28);
            overflow: clip;
            min-height: 100%;
            animation: panelIn 360ms cubic-bezier(.16, 1, .3, 1) both;
        }

        .panel-title {
            font-size: 0.95rem;
            font-weight: 900;
            color: #F6FDFF;
            margin-bottom: 0.25rem;
        }

        .panel-caption {
            color: var(--muted);
            font-size: 0.78rem;
            margin-bottom: 0.65rem;
            overflow-wrap: anywhere;
        }

        .matrix {
            display: grid;
            grid-template-columns: repeat(4, minmax(118px, 1fr));
            gap: 0.62rem;
        }

        .locker {
            position: relative;
            min-height: 104px;
            border-radius: 14px;
            padding: 0.68rem;
            background: linear-gradient(180deg, rgba(8, 13, 19, 0.92), rgba(2, 6, 10, 0.98));
            border: 1px solid rgba(31, 230, 255, 0.22);
            overflow: hidden;
            transition: transform 160ms cubic-bezier(.16, 1, .3, 1), border-color 160ms ease, box-shadow 160ms ease;
        }

        .locker:hover {
            transform: translateY(-2px);
            border-color: rgba(31, 230, 255, 0.62);
            box-shadow: 0 0 22px rgba(31, 230, 255, 0.12);
        }

        .locker::before {
            content: "";
            position: absolute;
            inset: -30%;
            background: linear-gradient(125deg, transparent 40%, rgba(255,255,255,0.12), transparent 58%);
            transform: translateX(-80%);
            transition: transform 450ms ease;
        }

        .locker:hover::before {
            transform: translateX(80%);
        }

        .locker-id {
            font-weight: 900;
            font-size: 1.18rem;
            color: #F6FDFF;
        }

        .locker-state {
            margin-top: 0.4rem;
            font-size: 0.72rem;
            color: var(--muted);
            font-weight: 800;
            overflow-wrap: anywhere;
        }

        .locker-sub {
            margin-top: 0.92rem;
            font-size: 0.72rem;
            color: #6D8A9D;
        }

        .locker.unlocked {
            border-color: rgba(45, 255, 154, 0.62);
            box-shadow: 0 0 24px rgba(45, 255, 154, 0.16), inset 0 0 24px rgba(45, 255, 154, 0.06);
        }

        .locker.unlocked .locker-state { color: var(--green); }

        .locker.selflocked {
            border-color: rgba(255, 59, 79, 0.78);
            box-shadow: 0 0 24px rgba(255, 59, 79, 0.20), inset 0 0 24px rgba(255, 59, 79, 0.07);
            animation: fault 1.1s steps(2, end) infinite;
        }

        .locker.selflocked .locker-state { color: var(--red); }

        @keyframes fault {
            0%, 100% { filter: saturate(1); }
            50% { filter: saturate(1.8) contrast(1.15); }
        }

        .locker-control-title {
            margin: 0.78rem 0 0.5rem 0;
            color: #F6FDFF;
            font-weight: 900;
            font-size: 0.86rem;
        }

        .locker-mini {
            min-height: 82px;
            border: 1px solid rgba(31, 230, 255, 0.16);
            border-radius: 12px;
            background: rgba(2, 6, 10, 0.68);
            padding: 0.54rem 0.58rem;
            margin-bottom: 0.36rem;
            overflow: hidden;
        }

        .locker-mini.good {
            border-color: rgba(45, 255, 154, 0.42);
            background: rgba(45, 255, 154, 0.07);
        }

        .locker-mini.bad {
            border-color: rgba(255, 59, 79, 0.50);
            background: rgba(255, 59, 79, 0.08);
        }

        .locker-mini-id {
            color: #F6FDFF;
            font-weight: 950;
            font-size: 0.95rem;
            line-height: 1.1;
        }

        .locker-mini-state {
            color: var(--cyan);
            font-weight: 900;
            font-size: 0.75rem;
            margin-top: 0.28rem;
            overflow-wrap: anywhere;
        }

        .locker-mini.good .locker-mini-state { color: var(--green); }
        .locker-mini.bad .locker-mini-state { color: var(--red); }

        .locker-mini-sub {
            color: var(--muted);
            font-size: 0.68rem;
            margin-top: 0.16rem;
            line-height: 1.22;
            overflow-wrap: anywhere;
        }

        .arsenal-card {
            border: 1px solid rgba(255, 176, 32, 0.34);
            border-radius: 14px;
            background: rgba(255, 176, 32, 0.05);
            padding: 0.62rem 0.7rem;
            margin-bottom: 0.5rem;
            overflow: hidden;
            position: relative;
        }

        .arsenal-card::after {
            content: "";
            position: absolute;
            inset: 0;
            background: linear-gradient(110deg, transparent, rgba(255,255,255,0.08), transparent);
            transform: translateX(-110%);
            animation: glare 7s ease-in-out infinite;
            pointer-events: none;
        }

        .arsenal-title {
            color: #FFF6DA;
            font-weight: 900;
            font-size: 0.78rem;
            margin-bottom: 0.16rem;
        }

        .arsenal-copy {
            color: #8AA4B8;
            font-size: 0.72rem;
            line-height: 1.38;
        }

        .logbox {
            max-height: 292px;
            overflow-y: auto;
            padding-right: 0.2rem;
        }

        .logrow {
            border-radius: 12px;
            border: 1px solid rgba(31, 230, 255, 0.16);
            padding: 0.65rem 0.7rem;
            margin-bottom: 0.55rem;
            background: rgba(4, 10, 17, 0.84);
        }

        .logrow.success { border-color: rgba(45, 255, 154, 0.42); }
        .logrow.warn { border-color: rgba(255, 176, 32, 0.48); }
        .logrow.error { border-color: rgba(255, 59, 79, 0.58); background: rgba(255, 59, 79, 0.08); }

        .logtitle {
            display: flex;
            justify-content: space-between;
            gap: 0.6rem;
            color: #F6FDFF;
            font-weight: 850;
            font-size: 0.86rem;
            min-width: 0;
        }

        .logtitle span {
            min-width: 0;
            overflow-wrap: anywhere;
        }

        .logmeta {
            margin-top: 0.34rem;
            color: var(--muted);
            font-size: 0.75rem;
            line-height: 1.45;
            overflow-wrap: anywhere;
            word-break: break-word;
        }

        .chart-wrap {
            position: relative;
            min-height: 196px;
            border-radius: 14px;
            border: 1px solid rgba(31, 230, 255, 0.12);
            background:
                linear-gradient(rgba(31, 230, 255, 0.04) 1px, transparent 1px),
                linear-gradient(90deg, rgba(31, 230, 255, 0.04) 1px, transparent 1px),
                rgba(2, 6, 10, 0.54);
            background-size: 24px 24px;
            overflow: hidden;
            padding: 0.45rem;
        }

        .chart-legend {
            display: flex;
            gap: 0.6rem;
            flex-wrap: wrap;
            color: var(--muted);
            font-size: 0.72rem;
            margin-top: 0.45rem;
        }

        .legend-dot {
            display: inline-block;
            width: 0.62rem;
            height: 0.62rem;
            border-radius: 999px;
            margin-right: 0.28rem;
        }

        .history-table {
            width: 100%;
            border-collapse: collapse;
            overflow: hidden;
            border-radius: 14px;
            font-size: 0.76rem;
        }

        .history-table th,
        .history-table td {
            border-bottom: 1px solid rgba(31, 230, 255, 0.10);
            padding: 0.48rem 0.5rem;
            text-align: left;
            color: #D9F8FF;
            vertical-align: top;
        }

        .history-table th {
            color: #8FEFFF;
            font-weight: 900;
            background: rgba(31, 230, 255, 0.08);
        }

        .history-table td {
            background: rgba(4, 10, 17, 0.56);
            overflow-wrap: anywhere;
        }

        .pill {
            display: inline-flex;
            border-radius: 999px;
            padding: 0.12rem 0.42rem;
            border: 1px solid rgba(31, 230, 255, 0.20);
            background: rgba(31, 230, 255, 0.08);
            color: #CFFBFF;
            font-size: 0.7rem;
            font-weight: 850;
        }

        .pill.good { border-color: rgba(45, 255, 154, 0.30); color: var(--green); background: rgba(45, 255, 154, 0.08); }
        .pill.bad { border-color: rgba(255, 59, 79, 0.36); color: var(--red); background: rgba(255, 59, 79, 0.08); }

        .kv-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 0.5rem;
        }

        .kv-cell {
            border: 1px solid rgba(31, 230, 255, 0.14);
            border-radius: 12px;
            background: rgba(2, 6, 10, 0.56);
            padding: 0.48rem 0.55rem;
            min-width: 0;
        }

        .kv-key {
            color: var(--muted);
            font-size: 0.68rem;
            font-weight: 800;
            margin-bottom: 0.18rem;
        }

        .kv-value {
            color: #F6FDFF;
            font-size: 0.82rem;
            font-weight: 850;
            overflow-wrap: anywhere;
        }

        .compare-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.75rem;
            margin: 0.35rem 0 0.55rem 0;
            color: #F6FDFF;
            font-weight: 900;
            font-size: 0.82rem;
        }

        .compare-badge {
            border: 1px solid rgba(31, 230, 255, 0.24);
            border-radius: 999px;
            padding: 0.16rem 0.5rem;
            color: var(--muted);
            font-size: 0.68rem;
            font-weight: 850;
            background: rgba(31, 230, 255, 0.06);
        }

        .evidence-note {
            border: 1px solid rgba(255, 176, 32, 0.30);
            border-radius: 12px;
            background: rgba(255, 176, 32, 0.06);
            color: #FFE7A8;
            padding: 0.55rem 0.62rem;
            font-size: 0.76rem;
            line-height: 1.45;
            margin: 0.5rem 0 0.65rem 0;
            overflow-wrap: anywhere;
        }

        .stButton > button {
            border-radius: 12px;
            font-weight: 850;
            border: 1px solid rgba(31, 230, 255, 0.32);
            background: rgba(31, 230, 255, 0.08);
            transition: transform 120ms cubic-bezier(.16, 1, .3, 1), box-shadow 160ms ease, border-color 160ms ease;
        }

        .stButton > button:hover {
            border-color: rgba(31, 230, 255, 0.74);
            box-shadow: 0 0 18px rgba(31, 230, 255, 0.14);
            transform: translateY(-1px);
        }

        .stButton > button:active {
            transform: translateY(0) scale(0.985);
        }

        .stMetric {
            border: 1px solid rgba(31, 230, 255, 0.14);
            border-radius: 14px;
            padding: 0.65rem 0.75rem;
            background: rgba(4, 10, 17, 0.72);
        }

        @media (prefers-reduced-motion: reduce) {
            .hero::after, .hero::before, .panel::after, .panel::before, .touch-console::before, .locker.selflocked, .flow-card::after, .arsenal-card::after { animation: none; }
            .locker, .stButton > button { transition: none; }
        }

        @media (max-height: 760px) {
            [data-testid="stSidebar"] [data-testid="stSidebarContent"] {
                padding-top: 0.55rem;
            }
            .touch-console { padding: 0.58rem 0.65rem; }
            .console-title { font-size: 1rem; }
            .console-subtitle, .console-chip, .arsenal-copy { font-size: 0.68rem; }
            [data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: 0.48rem; }
        }

        @media (max-width: 720px) {
            .hero-title { font-size: 1.45rem; }
            .dashboard-band { grid-template-columns: 1fr; }
            .matrix { grid-template-columns: repeat(auto-fit, minmax(116px, 1fr)); }
            .locker { min-height: 104px; padding: 0.62rem; }
            .kv-grid { grid-template-columns: 1fr; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero() -> None:
    st.markdown(
        f"""
        <div class="hero">
            <div class="hero-title">{APP_TITLE}</div>
            <div class="hero-sub">{APP_SUBTITLE} · 零知识证明 · 常量时间防护 · 固件金丝雀 · 混沌攻防</div>
            <div class="tag-row">
                <span class="tag cn">三步认证握手</span>
                <span class="tag cn">4x4 数字孪生柜</span>
                <span class="tag cn">时延侧信道实验</span>
                <span class="tag cn">固件内存沙箱</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_html_fragment(target, markup: str) -> None:
    if hasattr(st, "html"):
        target.html(markup)
    else:
        target.markdown(markup, unsafe_allow_html=True)


def render_sidebar() -> None:
    render_html_fragment(
        st.sidebar,
        """
        <div class="touch-console">
            <div class="console-kicker">校园柜触控端</div>
            <div class="console-title">取件认证终端</div>
            <div class="console-subtitle">选择格口、输入 6 位取件码，可在普通柜与零知识功能柜之间做对照实验。</div>
        </div>
        """,
    )
    selected = st.sidebar.selectbox(
        "格口选择",
        LOCKER_LABELS,
        index=locker_index(st.session_state.selected_locker),
    )
    st.session_state.selected_locker = selected
    demo_code = st.session_state.pickup_codes[selected]
    render_html_fragment(
        st.sidebar,
        f'<div class="console-code"><span>演示取件码</span><span>{demo_code}</span></div>',
    )
    code = st.sidebar.text_input("取件码", max_chars=6, placeholder="请输入 6 位数字")
    st.session_state.zero_trust_enabled = st.sidebar.toggle(
        "启用零知识功能外卖柜",
        value=st.session_state.zero_trust_enabled,
    )
    st.session_state.constant_time_enabled = bool(st.session_state.zero_trust_enabled)
    mode_text = "零知识功能外卖柜" if st.session_state.zero_trust_enabled else "普通外卖柜"
    mode_color = "#2DFF9A" if st.session_state.zero_trust_enabled else "#FFB020"
    render_html_fragment(
        st.sidebar,
        f'<div class="console-code" style="border-color:{mode_color};"><span>当前模式</span><span>{mode_text}</span></div>',
    )

    if st.sidebar.button("确认取件", width="stretch"):
        with st.sidebar.status("认证过程", expanded=True) as status_box:
            if st.session_state.zero_trust_enabled:
                status_box.write("终端：派生私钥 x，不上传明文")
                session = handle_normal_pickup(selected, code, True)
                status_box.write(f"承诺 X = {session.commitment_x}")
                status_box.write(f"挑战 c = {session.challenge_c}")
                status_box.write(f"响应 s = {session.response_s}")
                status_box.write(f"校验：左值 {session.left_value}，右值 {session.right_value}")
                if session.accepted:
                    status_box.update(label="零知识认证成功，格口弹开", state="complete")
                else:
                    status_box.update(label=f"认证失败：{session.reason}", state="error")
            else:
                status_box.write("普通柜：明文取件码进入服务器")
                plain_session = handle_plain_pickup(selected, code)
                status_box.write(f"设备编号 = {plain_session.device_id}")
                status_box.write(f"明文取件码 = {plain_session.pickup_code}")
                status_box.write(f"响应时长 = {plain_session.latency_ms:.3f} ms")
                status_box.write(f"匹配前缀 = {plain_session.matched_prefix}")
                if plain_session.accepted:
                    status_box.update(label="普通柜取件成功，格口弹开", state="complete")
                else:
                    status_box.update(label="普通柜取件失败，格口保持锁定", state="error")

    render_html_fragment(
        st.sidebar,
        """
        <div class="console-grid">
            <div class="console-chip">电源总线<br/>在线</div>
            <div class="console-chip">箱体温度<br/>31.8°C</div>
            <div class="console-chip">锁控总线<br/>待命</div>
            <div class="console-chip">网络策略<br/>零信任</div>
        </div>
        """,
    )

    if st.sidebar.button("全盘一键重置", width="stretch"):
        reset_state()
        st.rerun()


def render_matrix() -> None:
    tiles = []
    for label, state in zip(LOCKER_LABELS, st.session_state.locker_states):
        state_code, state_text = LOCKER_STATE_TEXT[state]
        class_name = "unlocked" if state == UNLOCKED else "selflocked" if state == SELF_LOCKED else "locked"
        sensor = f"温度 {28 + (locker_index(label) % 5)}.{locker_index(label) % 10}°C"
        tiles.append(
            (
                f'<div class="locker {class_name}">'
                f'<div class="locker-id">{label}</div>'
                f'<div class="locker-state">{state_code} · {state_text}</div>'
                f'<div class="locker-sub">{sensor}<br/>边缘节点 {locker_index(label)+1:02d}</div>'
                f"</div>"
            )
        )
    matrix_html = (
        '<div class="panel">'
        '<div class="panel-title">数字孪生格口矩阵</div>'
        '<div class="panel-caption">4x4 物理格口数字化双胞胎。青色为锁定，绿色为零知识解锁，红色为攻击自锁。</div>'
        '<div class="matrix">'
        + "".join(tiles)
        + "</div></div>"
    )
    if hasattr(st, "html"):
        st.html(matrix_html)
    else:
        st.markdown(matrix_html, unsafe_allow_html=True)

    st.markdown('<div class="locker-control-title">格口状态与柜门控制</div>', unsafe_allow_html=True)
    for row_start in range(0, LOCKER_COUNT, 4):
        cols = st.columns(4, gap="small")
        for col, label in zip(cols, LOCKER_LABELS[row_start: row_start + 4]):
            state = st.session_state.locker_states[locker_index(label)]
            state_code, state_text = LOCKER_STATE_TEXT[state]
            status_class = "good" if state == UNLOCKED else "bad" if state == SELF_LOCKED else "idle"
            with col:
                st.markdown(
                    (
                        f'<div class="locker-mini {status_class}">'
                        f'<div class="locker-mini-id">{label}</div>'
                        f'<div class="locker-mini-state">{state_code}</div>'
                        f'<div class="locker-mini-sub">{state_text}</div>'
                        f'</div>'
                    ),
                    unsafe_allow_html=True,
                )
                if state == LOCKED:
                    st.button("已关闭", key=f"close_{label}", disabled=True, width="stretch")
                else:
                    if st.button("关闭柜门" if state == UNLOCKED else "解除自锁", key=f"close_{label}", width="stretch"):
                        mark_locker(label, LOCKED)
                        push_trace(
                            "格口控制",
                            f"{label} 已手动关闭并恢复锁定",
                            locker=label,
                            decision="CLOSED",
                        )
                        push_log(
                            "success",
                            "格口状态手动复位",
                            f"{label} 已关闭，状态恢复为已锁定。",
                            locker=label,
                            decision="CLOSED",
                        )
                        st.rerun()


def render_metrics() -> None:
    health, health_status = compute_entropy_health()
    business_rate, defense_rate = compute_accuracy_metrics()
    total = len(st.session_state.request_history)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("信道健康熵值", f"{health:.1f}", health_status)
    m2.metric("业务正确率", f"{business_rate:.1f}%")
    m3.metric("防护拦截率", f"{defense_rate:.1f}%")
    m4.metric("请求样本", f"{total}", f"风险 {st.session_state.risk_score}")


def render_arsenal(locker: str) -> None:
    mode = "零知识功能外卖柜" if st.session_state.zero_trust_enabled else "普通外卖柜"
    st.markdown(f'<div class="panel"><div class="panel-title">混沌攻防武器库</div><div class="panel-caption">当前对照对象：{mode}。点击攻击按钮后，输入、报文、payload、阻断环节都会进入透明日志。</div>', unsafe_allow_html=True)

    st.markdown('<div class="arsenal-card"><div class="arsenal-title">时间侧信道</div><div class="arsenal-copy">普通柜逐位爆破；零知识柜展示被阻断环节。</div></div>', unsafe_allow_html=True)
    st.button("时间侧信道爆破", width="stretch", on_click=on_timing_attack, args=(locker,))

    st.markdown('<div class="arsenal-card"><div class="arsenal-title">历史报文重放</div><div class="arsenal-copy">展示完整旧报文，并标出是否被时间窗或缓存拦截。</div></div>', unsafe_allow_html=True)
    st.button("历史报文重放攻击", width="stretch", on_click=on_replay_attack, args=(locker,))

    st.markdown('<div class="arsenal-card"><div class="arsenal-title">固件溢出载荷</div><div class="arsenal-copy">逐条展示 payload、canary、CRC 和最终处置。</div></div>', unsafe_allow_html=True)
    st.button("恶意溢出载荷注入", width="stretch", on_click=on_overflow_attack, args=(locker,))

    feedback = st.session_state.last_attack_feedback
    if feedback:
        with st.status(str(feedback["label"]), expanded=True, state=str(feedback["state"])) as status_box:
            for line in feedback["lines"]:
                status_box.write(line)

    st.markdown("</div>", unsafe_allow_html=True)


def polyline_points(values: List[float], *, width: int = 720, height: int = 150, max_value: Optional[float] = None) -> str:
    if not values:
        return ""
    if len(values) == 1:
        values = values + values
    ceiling = max_value if max_value and max_value > 0 else max(max(values), 1.0)
    points = []
    for index, value in enumerate(values):
        x = 22 + index * ((width - 44) / max(len(values) - 1, 1))
        y = 18 + (height - 36) * (1 - clamp(value / ceiling, 0, 1))
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


def render_latency_svg(points: List[Dict[str, object]]) -> str:
    latencies = [float(item["latency_ms"]) for item in points]
    prefixes = [float(item["matched_prefix"]) for item in points]
    max_latency = max(max(latencies), 10.0)
    latency_line = polyline_points(latencies, max_value=max_latency)
    prefix_line = polyline_points(prefixes, max_value=6.0)
    return f"""
    <div class="chart-wrap">
        <svg viewBox="0 0 720 150" width="100%" height="150" role="img" aria-label="时延曲线">
            <defs>
                <linearGradient id="latencyGlow" x1="0" x2="1">
                    <stop offset="0%" stop-color="#1FE6FF" stop-opacity="0.1"/>
                    <stop offset="50%" stop-color="#1FE6FF" stop-opacity="1"/>
                    <stop offset="100%" stop-color="#2DFF9A" stop-opacity="0.8"/>
                </linearGradient>
            </defs>
            <line x1="22" y1="132" x2="698" y2="132" stroke="rgba(138,164,184,0.25)" />
            <line x1="22" y1="18" x2="22" y2="132" stroke="rgba(138,164,184,0.25)" />
            <polyline points="{latency_line}" fill="none" stroke="url(#latencyGlow)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />
            <polyline points="{prefix_line}" fill="none" stroke="#FFB020" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="5 6" />
        </svg>
        <div class="chart-legend">
            <span><i class="legend-dot" style="background:#1FE6FF;"></i>响应时延</span>
            <span><i class="legend-dot" style="background:#FFB020;"></i>匹配前缀</span>
            <span>样本数：{len(points)}</span>
        </div>
    </div>
    """


def render_latency_chart() -> None:
    st.markdown('<div class="panel"><div class="panel-title">时延遥测看板</div><div class="panel-caption">安全模式下曲线接近水平；非安全模式会随正确前缀变长而上升。</div>', unsafe_allow_html=True)
    points = list(st.session_state.latency_points)
    if points:
        chart_html = render_latency_svg(points)
        if hasattr(st, "html"):
            st.html(chart_html)
        else:
            st.markdown(chart_html, unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)
        latencies = [float(item["latency_ms"]) for item in points]
        jitters = [float(item["jitter_ms"]) for item in points]
        c1.metric("当前时延", f"{latencies[-1]:.2f} ms")
        c2.metric("峰值时延", f"{max(latencies):.2f} ms")
        c3.metric("平均抖动", f"{(sum(jitters) / len(jitters)):.2f} ms")
    else:
        st.info("暂无时延样本。点击右侧“时间侧信道爆破”或执行一次正常取件后生成曲线。")
    st.markdown("</div>", unsafe_allow_html=True)


def render_zkp_panel() -> None:
    title = "零知识握手记录" if st.session_state.zero_trust_enabled else "普通柜明文请求记录"
    caption = "展示最近一次 Schnorr 三步握手的公开资产，私钥 x 不显示。" if st.session_state.zero_trust_enabled else "展示普通柜最近一次明文取件请求，便于和零知识模式对比。"
    st.markdown(f'<div class="panel"><div class="panel-title">{title}</div><div class="panel-caption">{caption}</div>', unsafe_allow_html=True)
    session: Optional[ZKPSession] = st.session_state.last_zkp_session
    plain_session: Optional[PlainSession] = st.session_state.last_plain_session
    if not st.session_state.zero_trust_enabled:
        if plain_session is None:
            st.info("尚未执行普通柜取件。")
        else:
            rows = {
                "格口": plain_session.locker,
                "设备编号": plain_session.device_id,
                "明文取件码": plain_session.pickup_code,
                "时间戳": f"{plain_session.timestamp:.3f}",
                "随机数 nonce": plain_session.nonce,
                "响应时长": f"{plain_session.latency_ms:.3f} ms",
                "匹配前缀": plain_session.matched_prefix,
                "是否通过": "是" if plain_session.accepted else "否",
                "判定原因": plain_session.reason,
            }
            cells = "".join(
                (
                    '<div class="kv-cell">'
                    f'<div class="kv-key">{html.escape(str(key))}</div>'
                    f'<div class="kv-value">{html.escape(str(value))}</div>'
                    '</div>'
                )
                for key, value in rows.items()
            )
            render_html_fragment(st, f'<div class="kv-grid">{cells}</div>')
    elif session is None:
        st.info("尚未执行 ZKP 取件。")
    else:
        rows = {
            "格口": session.locker,
            "取件码哈希片段": session.pickup_hash_short,
            "公钥 y": session.public_y,
            "承诺 X": session.commitment_x,
            "挑战 c": session.challenge_c,
            "响应 s": session.response_s,
            "校验左值 g^s": session.left_value,
            "校验右值 X*y^c": session.right_value,
            "随机数 nonce": session.nonce,
            "是否通过": "是" if session.accepted else "否",
            "判定原因": reason_label(session.reason),
        }
        cells = "".join(
            (
                '<div class="kv-cell">'
                f'<div class="kv-key">{html.escape(str(key))}</div>'
                f'<div class="kv-value">{html.escape(str(value))}</div>'
                '</div>'
            )
            for key, value in rows.items()
        )
        block = f'<div class="kv-grid">{cells}</div>'
        render_html_fragment(st, block)
    st.markdown("</div>", unsafe_allow_html=True)


def render_transparency_panel() -> None:
    st.markdown('<div class="panel"><div class="panel-title">透明对照实验轨迹</div><div class="panel-caption">展示攻击输入、响应时长、重放报文、payload 和阻断环节。</div>', unsafe_allow_html=True)

    tabs = st.tabs(["时延爆破明细", "重放报文", "固件 payload", "步骤日志"])

    def table_value(value: object) -> str:
        if value is None or value == "":
            return ""
        if isinstance(value, float):
            return f"{value:.3f}"
        return str(value)

    def dataframe_rows(rows: List[Dict[str, object]]) -> None:
        st.dataframe(
            [{key: table_value(value) for key, value in row.items()} for row in rows],
            width="stretch",
            hide_index=True,
        )

    with tabs[0]:
        rows = list(st.session_state.latency_points)[-80:]
        if rows:
            table_rows = [
                {
                    "样本": table_value(item.get("sample")),
                    "候选输入": table_value(item.get("candidate")),
                    "平均时延 ms": table_value(item.get("avg_latency_ms", item.get("latency_ms"))),
                    "最小时延 ms": table_value(item.get("min_latency_ms", "")),
                    "最大时延 ms": table_value(item.get("max_latency_ms", "")),
                    "测量次数": table_value(item.get("measurements", "")),
                    "匹配前缀": table_value(item.get("matched_prefix")),
                    "模式": value_label(item.get("mode", "")),
                    "阻断环节": value_label(item.get("blocked_at", "")) if item.get("blocked_at") else "",
                    "是否通过": "是" if item.get("accepted") else "否",
                }
                for item in rows
            ]
            timing_summary = st.session_state.last_timing_summary
            if timing_summary:
                left_col, right_col = st.columns(2, gap="large")
                attack_rows = timing_summary.get("attack_samples", [])[-10:]
                reference_rows = timing_summary.get("reference_samples", [])
                with left_col:
                    st.markdown('<div class="compare-head"><span>攻击侧采样</span><span class="compare-badge">实际输入</span></div>', unsafe_allow_html=True)
                    dataframe_rows(
                        [
                            {
                                "候选输入": item.get("candidate", ""),
                                "平均时延 ms": item.get("avg_latency_ms", item.get("latency_ms", "")),
                                "匹配前缀": item.get("matched_prefix", ""),
                                "测量次数": item.get("measurements", ""),
                                "阻断环节": value_label(item.get("blocked_at", "")) if item.get("blocked_at") else "",
                            }
                            for item in attack_rows
                        ]
                    )
                with right_col:
                    st.markdown('<div class="compare-head"><span>安全侧对照</span><span class="compare-badge">正确防护</span></div>', unsafe_allow_html=True)
                    dataframe_rows(
                        [
                            {
                                "输入/流程": item.get("candidate", ""),
                                "固定时延 ms": item.get("avg_latency_ms", ""),
                                "前缀信号": item.get("matched_prefix", ""),
                                "检查项": value_label(item.get("check", "")),
                                "结果": value_label(item.get("result", "")),
                                "说明": item.get("reason", ""),
                            }
                            for item in reference_rows
                        ]
                    )
                blocked_at = timing_summary.get("blocked_at", "")
                note = (
                    f"对照结论：攻击样本试图通过响应时长推断取件码；安全侧不暴露明文逐位比较接口，"
                    f"阻断点为 {value_label(blocked_at)}。"
                    if blocked_at
                    else f"对照结论：普通柜可以根据平均时延逐位恢复取件码，恢复结果为 {timing_summary.get('recovered_code', '')}。"
                )
                st.markdown(f'<div class="evidence-note">{html.escape(note)}</div>', unsafe_allow_html=True)
            st.markdown("**完整采样明细**")
            dataframe_rows(table_rows)
        else:
            st.info("暂无时延样本。运行时间侧信道爆破后会显示每次输入和响应时长。")

    with tabs[1]:
        packet = st.session_state.last_replay_packet
        if packet:
            target_locker = st.session_state.last_replay_target_locker or st.session_state.selected_locker
            replay_mode = st.session_state.last_replay_mode == "zero_trust"
            reference_packet = reference_packet_for(target_locker, replay_mode)
            left_col, right_col = st.columns(2, gap="large")
            with left_col:
                st.markdown('<div class="compare-head"><span>攻击重放报文</span><span class="compare-badge">旧报文</span></div>', unsafe_allow_html=True)
                st.code(json.dumps(packet, ensure_ascii=False, indent=2), language="json")
            with right_col:
                st.markdown('<div class="compare-head"><span>正确新报文</span><span class="compare-badge">当前目标格口</span></div>', unsafe_allow_html=True)
                st.code(json.dumps(reference_packet, ensure_ascii=False, indent=2), language="json")
            if replay_mode:
                st.markdown(
                    '<div class="evidence-note">零知识正确报文每次都会重新生成 X、c、s、nonce 和 timestamp；'
                    '旧报文即使数学字段看起来完整，也会因为时间窗、摘要缓存或设备/格口绑定被拦截。</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    '<div class="evidence-note">普通柜对照重点：同柜旧报文仍可能通过，因为缺少时间窗和摘要缓存；'
                    '但跨柜报文必须在 device_id 或 locker 绑定处失败，不能让 A1 报文打开 A4。</div>',
                    unsafe_allow_html=True,
                )
            diff_rows = replay_difference_rows(packet, reference_packet, replay_mode)
            st.markdown("**字段差异对照**")
            dataframe_rows(diff_rows)
            replay_steps = st.session_state.last_replay_steps
            if replay_steps:
                step_rows = [
                    {
                        "步骤": item.get("序号"),
                        "检查项": value_label(item.get("check", "")),
                        "结果": value_label(item.get("result", "")),
                        "说明": item.get("detail", ""),
                        "阻断环节": value_label(item.get("blocked_at", "")) if item.get("blocked_at") else "",
                        "源格口": item.get("source_locker", ""),
                        "目标格口": item.get("target_locker", ""),
                        "源设备": item.get("source_device_id", ""),
                        "目标设备": item.get("target_device_id", ""),
                    }
                    for item in replay_steps
                ]
                st.markdown("**服务器校验链路**")
                dataframe_rows(step_rows)
        else:
            st.info("暂无可展示的重放报文。先执行一次取件或点击重放攻击。")

    with tabs[2]:
        rows = st.session_state.last_payload_rows
        if rows:
            overflow_locker = st.session_state.last_overflow_locker or st.session_state.selected_locker
            overflow_secure = st.session_state.last_overflow_mode == "zero_trust"
            reference_payload = reference_firmware_payload(overflow_locker, secure_mode=overflow_secure)
            attack_payload = rows[-1]
            left_col, right_col = st.columns(2, gap="large")
            with left_col:
                st.markdown('<div class="compare-head"><span>攻击 payload</span><span class="compare-badge">最后触发样本</span></div>', unsafe_allow_html=True)
                st.code(json.dumps(attack_payload, ensure_ascii=False, indent=2), language="json")
            with right_col:
                st.markdown('<div class="compare-head"><span>正确固件报文</span><span class="compare-badge">心跳样本</span></div>', unsafe_allow_html=True)
                st.code(json.dumps(reference_payload, ensure_ascii=False, indent=2), language="json")
            diff_rows = compare_dicts(
                attack_payload,
                reference_payload,
                ["payload_len", "payload_preview", "payload_hex", "canary_seen", "crc", "检查流水", "decision", "blocked_at"],
            )
            st.markdown("**payload 差异对照**")
            dataframe_rows(diff_rows)
            blocked_at = attack_payload.get("blocked_at", "")
            note = (
                f"对照结论：攻击 payload 在 {value_label(blocked_at)} 处被阻断，正确心跳报文会顺序通过长度、金丝雀和 CRC 检查。"
                if blocked_at
                else "对照结论：普通柜跳过长度、金丝雀和 CRC 检查，越界 payload 会继续被处理。"
            )
            st.markdown(f'<div class="evidence-note">{html.escape(note)}</div>', unsafe_allow_html=True)
            st.markdown("**完整 payload 样本**")
            dataframe_rows(rows)
        else:
            st.info("暂无 payload 样本。运行固件溢出载荷攻击后会显示每次 payload。")

    with tabs[3]:
        traces = list(st.session_state.trace_rows)[:80]
        if traces:
            trace_rows = []
            for item in traces:
                fields = item.get("fields", {})
                trace_rows.append(
                    {
                        "时间": time_label(float(item["ts"])),
                        "阶段": item["stage"],
                        "说明": item["detail"],
                        "关键字段": " · ".join(
                            f"{field_label(k)}={value_label(v)}" for k, v in fields.items()
                        ),
                    }
                )
            dataframe_rows(trace_rows)
        else:
            st.info("暂无实验步骤日志。")
    st.markdown("</div>", unsafe_allow_html=True)


def log_html(entry: Dict[str, object]) -> str:
    level = html.escape(str(entry["level"]))
    title = html.escape(str(entry["title"]))
    message = html.escape(reason_label(str(entry["message"])))
    fields = entry.get("fields", {})
    field_text = " · ".join(
        f"{html.escape(field_label(k))}={html.escape(value_label(v))}"
        for k, v in fields.items()
    )
    return (
        f'<div class="logrow {level}">'
        f'<div class="logtitle"><span>{title}</span><span>{time_label(float(entry["ts"]))}</span></div>'
        f'<div class="logmeta">{message}<br/>{field_text}</div>'
        f"</div>"
    )


def render_protocol_flow() -> None:
    st.markdown(
        """
        <div class="dashboard-band">
            <div class="flow-card">
                <div class="flow-title">认证资产流动</div>
                <div class="flow-copy">触控端只提交公开承诺 X、挑战响应 s 与随机数；后台使用公钥 y 验证等式，不需要接收明文取件码。</div>
            </div>
            <div class="flow-card">
                <div class="flow-title">风控联动</div>
                <div class="flow-copy">攻击按钮会同时驱动格口自锁、熵值下降、时延曲线和审计日志，形成完整闭环演示。</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def on_timing_attack(locker: str) -> None:
    result = run_timing_side_channel(locker, st.session_state.zero_trust_enabled)
    lines = [f"样本数：{len(result['samples'])}", reason_label(str(result["reason"]))]
    if result.get("blocked_at"):
        lines.append(f"阻断环节：{value_label(result['blocked_at'])}")
    if result.get("recovered_code"):
        lines.append(f"恢复出的取件码：{result['recovered_code']}")
    st.session_state.last_attack_feedback = {
        "label": "时延实验完成",
        "state": "complete" if result.get("blocked", True) else "error",
        "lines": lines,
    }


def on_replay_attack(locker: str) -> None:
    result = simulate_replay_attack(locker, st.session_state.zero_trust_enabled)
    lines = [reason_label(str(result["reason"]))]
    steps = result.get("steps", [])
    if steps:
        passed = [value_label(item.get("check", "")) for item in steps if item.get("result") in ("PASS", "SKIP")]
        if passed:
            lines.append("已执行步骤：" + " → ".join(passed[-5:]))
    if result.get("blocked_at"):
        lines.append(f"阻断环节：{value_label(result['blocked_at'])}")
    packet = result.get("packet", {})
    if packet:
        lines.append(f"报文所属格口：{packet.get('locker', '')}，当前攻击目标：{locker}")
    st.session_state.last_attack_feedback = {
        "label": "重放检测完成",
        "state": "complete" if result["blocked"] else "error",
        "lines": lines,
    }


def on_overflow_attack(locker: str) -> None:
    result = simulate_overflow_attack(locker, st.session_state.zero_trust_enabled)
    lines = [reason_label(str(result["reason"])), f"payload 样本数：{len(result.get('rows', []))}"]
    if result.get("blocked_at"):
        lines.append(f"阻断环节：{value_label(result['blocked_at'])}")
    st.session_state.last_attack_feedback = {
        "label": "栈金丝雀检测完成",
        "state": "complete" if result["blocked"] else "error",
        "lines": lines,
    }


def render_logs() -> None:
    st.markdown('<div class="panel"><div class="panel-title">入侵检测审计台</div><div class="panel-caption">每条记录保留攻击证据、验证资产、判定原因和风险影响。</div>', unsafe_allow_html=True)
    logs = list(st.session_state.audit_logs)
    if not logs:
        st.info("等待第一条认证或攻击事件。")
    else:
        block = '<div class="logbox">' + "".join(log_html(item) for item in logs[:30]) + "</div>"
        if hasattr(st, "html"):
            st.html(block)
        else:
            st.markdown(block, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


def render_history_table() -> None:
    st.markdown('<div class="panel"><div class="panel-title">请求状态机轨迹</div><div class="panel-caption">最近请求状态机轨迹：通过、拒绝、拦截与对应风险变化。</div>', unsafe_allow_html=True)
    rows = list(st.session_state.request_history)[:18]
    if rows:
        html_rows = []
        for item in rows:
            accepted = bool(item["accepted"])
            attack = bool(item["attack"])
            status = "通过" if accepted else "拦截" if attack else "拒绝"
            status_class = "good" if accepted else "bad"
            html_rows.append(
                "<tr>"
                f"<td>{html.escape(time_label(float(item['ts'])))}</td>"
                f"<td>{html.escape(str(item['locker']))}</td>"
                f"<td>{html.escape(event_label(str(item['event_type'])))}</td>"
                f'<td><span class="pill {status_class}">{status}</span></td>'
                f"<td>{html.escape(reason_label(str(item['reason'])))}</td>"
                f"<td>{html.escape(str(item['risk_delta']))}</td>"
                "</tr>"
            )
        table_html = (
            '<table class="history-table">'
            "<thead><tr><th>时间</th><th>格口</th><th>事件</th><th>判定</th><th>原因</th><th>风险</th></tr></thead>"
            "<tbody>"
            + "".join(html_rows)
            + "</tbody></table>"
        )
        if hasattr(st, "html"):
            st.html(table_html)
        else:
            st.markdown(table_html, unsafe_allow_html=True)
    else:
        st.info("暂无请求历史。")
    st.markdown("</div>", unsafe_allow_html=True)


def main() -> None:
    st.set_page_config(
        page_title="AegisCabinet-Zero",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_state()
    inject_css()
    render_sidebar()
    render_hero()
    render_metrics()
    render_protocol_flow()

    selected_locker = st.session_state.selected_locker
    main_col, right_col = st.columns([1.55, 1.0], gap="large")
    with main_col:
        render_matrix()
        render_logs()
    with right_col:
        render_arsenal(selected_locker)
        render_zkp_panel()
        render_latency_chart()

    render_transparency_panel()
    render_history_table()
    st.caption(
        "AegisCabinet-Zero 是纯软件仿真系统。Schnorr 群参数为教学用途，生产系统需替换为成熟曲线、硬件安全模块和 TLS 传输。"
    )


if __name__ == "__main__":
    main()
