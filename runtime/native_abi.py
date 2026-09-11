"""
JOCKY Native Runtime ABI Bridge
Bridges C-compatible callback functions emitted by the LLVM compiler directly to the
ForensicRuntime, platform adapters, and normalized forensic collectors.
"""
import ctypes
import os
from typing import Any, Dict, List, Optional

from runtime.forensic_runtime import ForensicRuntime, RuntimeContext

# Active runtime singleton
_FORENSIC_RUNTIME: Optional[ForensicRuntime] = None
_STRING_CACHE: List[Any] = []  # Keep string buffers alive during execution


def get_runtime() -> ForensicRuntime:
    global _FORENSIC_RUNTIME
    if _FORENSIC_RUNTIME is None:
        _FORENSIC_RUNTIME = ForensicRuntime()
    return _FORENSIC_RUNTIME


def set_runtime(runtime: ForensicRuntime):
    global _FORENSIC_RUNTIME
    _FORENSIC_RUNTIME = runtime


def reset_context() -> RuntimeContext:
    global _STRING_CACHE, _collection_cache, _entity_cache
    _STRING_CACHE.clear()
    _collection_cache.clear()
    _entity_cache.clear()
    rt = get_runtime()
    rt.reset()
    return rt.context


# Backward compatibility alias
def _get_current_context():
    return get_runtime().context


class _ContextProxy:
    def __getattr__(self, name):
        return getattr(get_runtime().context, name)

    def __setattr__(self, name, value):
        setattr(get_runtime().context, name, value)


CURRENT_CONTEXT = _ContextProxy()


# Property ID to dictionary key mapping for compiled entity queries
PROP_ID_MAP = {
    # Process
    1: "pid",
    2: "ppid",
    3: "name",
    4: "exe_path",
    5: "cmdline",
    6: "username",
    7: "created_time",
    8: "status",
    9: "threads",
    10: "memory_bytes",
    # Network
    101: "protocol",
    102: "local_ip",
    103: "local_port",
    104: "remote_ip",
    105: "remote_port",
    106: "status",
    107: "pid",
    # Files
    201: "path",
    202: "size",
    203: "modified_time",
    204: "permissions",
    205: "md5",
    206: "sha256",
    # EventLog
    301: "source",
    302: "event_id",
    303: "level",
    304: "message",
    # Registry
    401: "key",
    402: "value_name",
    403: "value_data",
}

# Handle caches for opaque pointer passing to compiled code
_collection_cache: Dict[int, List[Dict[str, Any]]] = {}
_entity_cache: Dict[int, Dict[str, Any]] = {}
_next_handle = 1000


def _keep_string(text: str) -> int:
    """Allocate and retain C string buffer to prevent GC before native dereference."""
    b = text.encode("utf-8")
    buf = ctypes.create_string_buffer(b)
    _STRING_CACHE.append(buf)
    return ctypes.cast(buf, ctypes.c_void_p).value or 0


# ============================================================================
# Ctypes Callback Functions matching ABI Signatures
# ============================================================================

@ctypes.CFUNCTYPE(None)
def jocky_rt_init():
    pass


@ctypes.CFUNCTYPE(None, ctypes.c_int32, ctypes.c_char_p)
def jocky_set_target(target_type, host_str):
    rt = get_runtime()
    hostname = host_str.decode("utf-8", errors="ignore") if host_str else ""
    rt.set_target(target_type, hostname)


@ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_char_p)
def jocky_set_config(key, val):
    rt = get_runtime()
    k = key.decode("utf-8", errors="ignore") if key else ""
    v = val.decode("utf-8", errors="ignore") if val else ""
    rt.set_config(k, v)


# Scans — Dispatched through ForensicRuntime -> Adapter -> Collectors
@ctypes.CFUNCTYPE(None)
def jocky_scan_processes():
    get_runtime().scan_processes()


@ctypes.CFUNCTYPE(None)
def jocky_scan_files():
    get_runtime().scan_files()


@ctypes.CFUNCTYPE(None)
def jocky_scan_network():
    get_runtime().scan_network()


@ctypes.CFUNCTYPE(None)
def jocky_scan_eventlogs():
    get_runtime().scan_eventlogs()


@ctypes.CFUNCTYPE(None)
def jocky_scan_registry():
    get_runtime().scan_registry()


@ctypes.CFUNCTYPE(None)
def jocky_scan_all():
    get_runtime().scan_all()


# Finds
@ctypes.CFUNCTYPE(None)
def jocky_find_ioc():
    get_runtime().context.executed_finds.append("IOC")


@ctypes.CFUNCTYPE(None)
def jocky_find_suspicious():
    get_runtime().context.executed_finds.append("SUSPICIOUS")


@ctypes.CFUNCTYPE(None)
def jocky_find_malware():
    get_runtime().context.executed_finds.append("MALWARE")


@ctypes.CFUNCTYPE(None)
def jocky_find_persistence():
    get_runtime().context.executed_finds.append("PERSISTENCE")


# Builds
@ctypes.CFUNCTYPE(None)
def jocky_build_timeline():
    get_runtime().context.executed_builds.append("TIMELINE")


@ctypes.CFUNCTYPE(None)
def jocky_build_correlations():
    get_runtime().context.executed_builds.append("CORRELATIONS")


@ctypes.CFUNCTYPE(None)
def jocky_build_processgraph():
    get_runtime().context.executed_builds.append("PROCESSGRAPH")


# Exports
@ctypes.CFUNCTYPE(None, ctypes.c_char_p)
def jocky_export_report(path):
    p = path.decode("utf-8", errors="ignore") if path else ""
    get_runtime().export_report(p)


@ctypes.CFUNCTYPE(None, ctypes.c_char_p)
def jocky_export_evidence(path):
    p = path.decode("utf-8", errors="ignore") if path else ""
    get_runtime().export_evidence(p)


@ctypes.CFUNCTYPE(None, ctypes.c_char_p)
def jocky_export_timeline(path):
    p = path.decode("utf-8", errors="ignore") if path else ""
    get_runtime().export_timeline(p)


# Collection and Loop Iteration ABI
@ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int32)
def jocky_get_collection(source_id):
    global _next_handle
    items = get_runtime().get_collection(source_id)
    _next_handle += 1
    _collection_cache[_next_handle] = items
    return _next_handle


@ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p)
def jocky_collection_count(coll_ptr):
    items = _collection_cache.get(coll_ptr, [])
    return len(items)


@ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
def jocky_collection_get_item(coll_ptr, index):
    global _next_handle
    items = _collection_cache.get(coll_ptr, [])
    if 0 <= index < len(items):
        _next_handle += 1
        _entity_cache[_next_handle] = items[index]
        return _next_handle
    return 0


# Property Extraction ABI
@ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p, ctypes.c_int32)
def jocky_entity_get_int(entity_ptr, prop_id):
    entity = _entity_cache.get(entity_ptr, {})
    prop_name = PROP_ID_MAP.get(prop_id, "")
    val = entity.get(prop_name, 0)
    return int(val) if isinstance(val, (int, float)) else 0


@ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int32)
def jocky_entity_get_str(entity_ptr, prop_id):
    entity = _entity_cache.get(entity_ptr, {})
    prop_name = PROP_ID_MAP.get(prop_id, "")
    val = entity.get(prop_name, "")
    return _keep_string(str(val))


@ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p)
def jocky_str_contains(s1, s2):
    str1 = s1.decode("utf-8", errors="ignore").lower() if s1 else ""
    str2 = s2.decode("utf-8", errors="ignore").lower() if s2 else ""
    return str2 in str1


# Export dictionary for LLVM dynamic symbol resolution
ABI_SYMBOLS = {
    "jocky_rt_init": jocky_rt_init,
    "jocky_set_target": jocky_set_target,
    "jocky_set_config": jocky_set_config,
    "jocky_scan_processes": jocky_scan_processes,
    "jocky_scan_files": jocky_scan_files,
    "jocky_scan_network": jocky_scan_network,
    "jocky_scan_eventlogs": jocky_scan_eventlogs,
    "jocky_scan_registry": jocky_scan_registry,
    "jocky_scan_all": jocky_scan_all,
    "jocky_find_ioc": jocky_find_ioc,
    "jocky_find_suspicious": jocky_find_suspicious,
    "jocky_find_malware": jocky_find_malware,
    "jocky_find_persistence": jocky_find_persistence,
    "jocky_build_timeline": jocky_build_timeline,
    "jocky_build_correlations": jocky_build_correlations,
    "jocky_build_processgraph": jocky_build_processgraph,
    "jocky_export_report": jocky_export_report,
    "jocky_export_evidence": jocky_export_evidence,
    "jocky_export_timeline": jocky_export_timeline,
    "jocky_get_collection": jocky_get_collection,
    "jocky_collection_count": jocky_collection_count,
    "jocky_collection_get_item": jocky_collection_get_item,
    "jocky_entity_get_int": jocky_entity_get_int,
    "jocky_entity_get_str": jocky_entity_get_str,
    "jocky_str_contains": jocky_str_contains,
}
