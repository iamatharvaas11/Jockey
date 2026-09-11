class CorrelationEngine:
    def __init__(self, processes, connections, events, files, registry):
        self.processes = processes or []
        self.connections = connections or []
        self.events = events or []
        self.files = files or []
        self.registry = registry or []
        
        self.proc_map = {p.get('pid'): p for p in self.processes if p.get('pid') is not None}
        self.file_map = {f.get('path'): f for f in self.files if f.get('path')}

    def correlate_network_to_process(self) -> list[dict]:
        results = []
        for conn in self.connections:
            pid = conn.get('pid')
            enriched = dict(conn)
            if pid in self.proc_map:
                proc = self.proc_map[pid]
                enriched['process_name'] = proc.get('name')
                enriched['process_exe'] = proc.get('exe_path')
                enriched['process_cmdline'] = proc.get('cmdline')
            else:
                enriched['process_name'] = "Unknown"
            results.append(enriched)
        return results

    def correlate_process_to_files(self) -> list[dict]:
        results = []
        for proc in self.processes:
            exe = proc.get('exe_path')
            enriched = dict(proc)
            if exe and exe in self.file_map:
                finfo = self.file_map[exe]
                enriched['file_md5'] = finfo.get('md5')
                enriched['file_sha256'] = finfo.get('sha256')
                enriched['file_created'] = finfo.get('created_time')
            results.append(enriched)
        return results

    def build_process_tree(self) -> dict:
        tree = {}
        nodes = {}
        for p in self.processes:
            pid = p.get('pid')
            if pid is not None:
                nodes[pid] = {
                    'pid': pid,
                    'ppid': p.get('ppid', 0),
                    'name': p.get('name', ''),
                    'exe_path': p.get('exe_path', ''),
                    'children': []
                }
        
        for pid, node in nodes.items():
            ppid = node['ppid']
            if ppid in nodes and ppid != pid:
                nodes[ppid]['children'].append(node)
            else:
                tree[pid] = node
        return tree


    def find_suspicious_chains(self) -> list[dict]:
        suspicious = []
        rules = [
            {"parent": "winword.exe", "child": "cmd.exe"},
            {"parent": "excel.exe", "child": "cmd.exe"},
            {"parent": "explorer.exe", "child": "cmd.exe"},
            {"parent": "cmd.exe", "child": "powershell.exe"}
        ]
        
        for p in self.processes:
            p_name = p.get('name', '').lower()
            ppid = p.get('ppid')
            if ppid in self.proc_map:
                parent_name = self.proc_map[ppid].get('name', '').lower()
                for rule in rules:
                    if rule['parent'] == parent_name and rule['child'] == p_name:
                        suspicious.append({
                            "type": "suspicious_process_chain",
                            "parent": self.proc_map[ppid],
                            "child": p
                        })
        return suspicious

    def correlate_all(self) -> dict:
        return {
            "network_to_process": self.correlate_network_to_process(),
            "process_to_files": self.correlate_process_to_files(),
            "process_tree": self.build_process_tree(),
            "suspicious_chains": self.find_suspicious_chains()
        }
