#!/usr/bin/env python3
"""
Log Aggregator - Centralized log collection and alerting

Features:
- Multiple source support
- Pattern matching
- Alert generation
- Real-time monitoring
- JSON output
- Filtering
"""

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
import threading
from queue import Queue

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


@dataclass
class LogEntry:
    timestamp: str
    source: str
    level: str
    message: str
    raw: str


@dataclass
class Alert:
    timestamp: str
    source: str
    pattern: str
    message: str
    count: int


# Default alert patterns
ALERT_PATTERNS = [
    (r'error|fail|critical|fatal', 'error', 'Error detected'),
    (r'unauthorized|forbidden|denied', 'security', 'Access denied'),
    (r'timeout|timed out', 'performance', 'Timeout occurred'),
    (r'out of memory|oom|memory limit', 'resource', 'Memory issue'),
    (r'disk full|no space', 'resource', 'Disk space issue'),
    (r'connection refused|unreachable', 'network', 'Connection issue'),
    (r'injection|xss|csrf', 'security', 'Security attack pattern'),
    (r'brute.?force|too many attempts', 'security', 'Brute force detected'),
]


class LogAggregator:
    def __init__(self):
        self.entries: List[LogEntry] = []
        self.alerts: List[Alert] = []
        self.stats = defaultdict(int)
        self.level_counts = defaultdict(int)
        self.source_counts = defaultdict(int)
        self.alert_counts = defaultdict(int)
        
    def parse_log_line(self, line: str, source: str) -> Optional[LogEntry]:
        """Parse a log line and extract components"""
        line = line.strip()
        if not line:
            return None
        
        # Try common log formats
        # Syslog format
        syslog_match = re.match(
            r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s*(.*)$',
            line
        )
        if syslog_match:
            return LogEntry(
                timestamp=syslog_match.group(1),
                source=source,
                level='info',
                message=syslog_match.group(4),
                raw=line
            )
        
        # Apache/Nginx access log
        access_match = re.match(
            r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)',
            line
        )
        if access_match:
            status = int(access_match.group(4))
            level = 'error' if status >= 400 else 'info'
            return LogEntry(
                timestamp=access_match.group(2),
                source=source,
                level=level,
                message=f"{access_match.group(3)} -> {status}",
                raw=line
            )
        
        # JSON log
        try:
            data = json.loads(line)
            return LogEntry(
                timestamp=data.get('timestamp', data.get('time', '')),
                source=source,
                level=data.get('level', data.get('severity', 'info')).lower(),
                message=data.get('message', data.get('msg', '')),
                raw=line
            )
        except:
            pass
        
        # Generic log with level
        level_match = re.match(
            r'^[\[\(]?(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}[^\]\)]*)?[\]\)]?\s*'
            r'[\[\(]?(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)[\]\)]?\s*:?\s*(.*)$',
            line, re.I
        )
        if level_match:
            return LogEntry(
                timestamp=level_match.group(1) or '',
                source=source,
                level=level_match.group(2).lower()[:4].replace('warn', 'warn'),
                message=level_match.group(3),
                raw=line
            )
        
        # Default: treat as info
        return LogEntry(
            timestamp='',
            source=source,
            level='info',
            message=line,
            raw=line
        )
    
    def check_alerts(self, entry: LogEntry):
        """Check entry against alert patterns"""
        for pattern, category, description in ALERT_PATTERNS:
            if re.search(pattern, entry.message, re.I):
                key = f"{entry.source}:{category}"
                self.alert_counts[key] += 1
                
                # Generate alert on first occurrence or every 10
                if self.alert_counts[key] == 1 or self.alert_counts[key] % 10 == 0:
                    alert = Alert(
                        timestamp=datetime.now().isoformat(),
                        source=entry.source,
                        pattern=category,
                        message=f"{description}: {entry.message[:100]}",
                        count=self.alert_counts[key]
                    )
                    self.alerts.append(alert)
                    return alert
        return None
    
    def process_file(self, filepath: str):
        """Process a log file"""
        source = Path(filepath).name
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    entry = self.parse_log_line(line, source)
                    if entry:
                        self.entries.append(entry)
                        self.stats['total'] += 1
                        self.level_counts[entry.level] += 1
                        self.source_counts[source] += 1
                        
                        alert = self.check_alerts(entry)
                        if alert:
                            self.print_alert(alert)
        except Exception as e:
            print(f"{Colors.RED}Error reading {filepath}: {e}{Colors.RESET}")
    
    def tail_file(self, filepath: str, callback=None):
        """Tail a file for new entries"""
        source = Path(filepath).name
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                # Seek to end
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if line:
                        entry = self.parse_log_line(line, source)
                        if entry:
                            self.entries.append(entry)
                            self.stats['total'] += 1
                            
                            if callback:
                                callback(entry)
                            
                            alert = self.check_alerts(entry)
                            if alert:
                                self.print_alert(alert)
                    else:
                        time.sleep(0.1)
        except KeyboardInterrupt:
            pass
    
    def print_entry(self, entry: LogEntry):
        """Print a log entry with colors"""
        level_colors = {
            'error': Colors.RED,
            'erro': Colors.RED,
            'warn': Colors.YELLOW,
            'info': Colors.GREEN,
            'debug': Colors.DIM,
            'fatal': Colors.RED,
            'crit': Colors.RED,
        }
        
        color = level_colors.get(entry.level[:4], Colors.RESET)
        
        print(f"{Colors.DIM}{entry.timestamp}{Colors.RESET} ", end="")
        print(f"{Colors.CYAN}{entry.source:20}{Colors.RESET} ", end="")
        print(f"{color}[{entry.level.upper():5}]{Colors.RESET} ", end="")
        print(entry.message[:80])
    
    def print_alert(self, alert: Alert):
        """Print alert"""
        print(f"\n{Colors.RED}{'═' * 60}")
        print(f"  [!]  ALERT: {alert.pattern.upper()}")
        print(f"  Source: {alert.source}")
        print(f"  Count: {alert.count}")
        print(f"  {alert.message}")
        print(f"{'═' * 60}{Colors.RESET}\n")
    
    def get_summary(self) -> Dict:
        """Get aggregation summary"""
        return {
            'total_entries': self.stats['total'],
            'by_level': dict(self.level_counts),
            'by_source': dict(self.source_counts),
            'alerts': len(self.alerts),
            'alert_patterns': dict(self.alert_counts)
        }


def print_banner():
    print(f"""{Colors.CYAN}
  _                        _                    _             
 | |    ___   __ _        / \   __ _  __ _ _ __| | ___  __ _ 
 | |   / _ \ / _` |      / _ \ / _` |/ _` | '__| |/ _ \/ _` |
 | |__| (_) | (_| |     / ___ \ (_| | (_| | |  | |  __/ (_| |
 |_____\___/ \__, |    /_/   \_\__, |\__, |_|  |_|\___|\__, |
             |___/             |___/ |___/             |___/ 
{Colors.RESET}                                              v{VERSION}
""")


def demo_mode():
    """Run demo"""
    print(f"{Colors.CYAN}Running demo...{Colors.RESET}\n")
    
    aggregator = LogAggregator()
    
    sample_logs = [
        "2024-01-15 10:30:01 [INFO] Application started",
        "2024-01-15 10:30:05 [INFO] Connected to database",
        "2024-01-15 10:30:10 [WARN] High memory usage detected",
        "2024-01-15 10:30:15 [ERROR] Failed to process request: timeout",
        "2024-01-15 10:30:20 [INFO] Request processed successfully",
        "2024-01-15 10:30:25 [ERROR] Connection refused to external service",
        "2024-01-15 10:30:30 [WARN] Unauthorized access attempt from 192.168.1.100",
    ]
    
    for line in sample_logs:
        entry = aggregator.parse_log_line(line, "app.log")
        if entry:
            aggregator.entries.append(entry)
            aggregator.stats['total'] += 1
            aggregator.level_counts[entry.level] += 1
            aggregator.print_entry(entry)
            aggregator.check_alerts(entry)
            time.sleep(0.3)
    
    summary = aggregator.get_summary()
    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"  Total entries: {summary['total_entries']}")
    print(f"  By level: {summary['by_level']}")
    print(f"  Alerts: {summary['alerts']}")


def main():
    parser = argparse.ArgumentParser(description="Log Aggregator")
    parser.add_argument("files", nargs="*", help="Log files to process")
    parser.add_argument("-f", "--follow", action="store_true", help="Follow file")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    if not args.files:
        print(f"{Colors.YELLOW}No files specified. Use --demo for demonstration.{Colors.RESET}")
        return
    
    aggregator = LogAggregator()
    
    if args.follow and len(args.files) == 1:
        print(f"Tailing {args.files[0]}... (Ctrl+C to stop)\n")
        aggregator.tail_file(args.files[0], callback=aggregator.print_entry)
    else:
        for filepath in args.files:
            print(f"Processing {filepath}...")
            aggregator.process_file(filepath)
    
    summary = aggregator.get_summary()
    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"  Total entries: {summary['total_entries']}")
    print(f"  By level: {json.dumps(summary['by_level'])}")
    print(f"  Alerts: {summary['alerts']}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                'summary': summary,
                'alerts': [asdict(a) for a in aggregator.alerts]
            }, f, indent=2)
        print(f"\n{Colors.GREEN}Results saved to: {args.output}{Colors.RESET}")


if __name__ == "__main__":
    main()
