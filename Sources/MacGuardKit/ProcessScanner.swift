import Foundation

public struct ProcInfo {
    public var pid: Int32
    public var ppid: Int32
    public var uid: UInt32
    public var comm: String
    public var path: String?
    public var args: [String]
    public var cpuPercent: Double
    public var startTime: Date?

    public var parentName: String { ppid <= 0 ? "launchd" : "pid:\(ppid)" }
}

public struct ListeningSocket {
    public var pid: Int32?
    public var process: String
    public var address: String
    public var port: Int
    public var isPrivileged: Bool { port < 1024 }
}

public enum ProcessScanner {
    public static func allProcesses() -> [ProcInfo] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var len = 0
        guard sysctl(&mib, 4, nil, &len, nil, 0) == 0, len > 0 else { return [] }

        let stride = MemoryLayout<kinfo_proc>.stride
        let count = len / stride
        var buffer = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, 4, &buffer, &len, nil, 0) == 0 else { return [] }

        let usable = min(len / stride, count)
        var out: [ProcInfo] = []
        out.reserveCapacity(usable)

        let bootEpoch = Date().timeIntervalSince1970 - uptimeSeconds()
        for i in 0..<usable {
            let entry = buffer[i]
            let kp = entry.kp_proc
            guard kp.p_pid > 0 else { continue }
            let startedAgo = now() - Double(kp.p_starttime.tv_sec)
            var info = ProcInfo(
                pid: kp.p_pid,
                ppid: entry.kp_eproc.e_ppid,
                uid: entry.kp_eproc.e_ucred.cr_uid,
                comm: cString(kp.p_comm),
                path: executablePath(pid: kp.p_pid),
                args: arguments(pid: kp.p_pid, uid: entry.kp_eproc.e_ucred.cr_uid),
                cpuPercent: cpuPercent(pid: kp.p_pid, elapsed: max(startedAgo, 1)),
                startTime: Date(timeIntervalSince1970: bootEpoch + Double(kp.p_starttime.tv_sec))
            )
            if info.path == nil || info.path?.isEmpty == true {
                info.path = executablePath(pid: kp.p_pid, followSymlinks: false)
            }
            out.append(info)
        }
        return out
    }

    private static func cString<T>(_ value: T) -> String {
        withUnsafeBytes(of: value) { raw in
            let bytes = [UInt8](raw)
            if let end = bytes.firstIndex(of: 0) {
                return String(decoding: bytes[0..<end], as: UTF8.self)
            }
            return String(decoding: bytes, as: UTF8.self)
        }
    }

    /// proc_pidpath has no exported max-size constant in Swift; 4 * MAXPATHLEN is the ABI value.
    private static let maxPathLength = 4 * 1024

    private static func executablePath(pid: Int32, followSymlinks: Bool = true) -> String? {
        var buffer = [CChar](repeating: 0, count: maxPathLength)
        let written = proc_pidpath(pid, &buffer, UInt32(maxPathLength))
        guard written > 0 else { return nil }
        let path = String(cString: buffer)
        guard !path.isEmpty else { return nil }
        if followSymlinks {
            let resolved = (path as NSString).resolvingSymlinksInPath
            return PathUtil.exists(resolved) ? resolved : path
        }
        return path
    }

    /// Reads argv via KERN_PROCARGS2. Only permitted for our own processes unless root.
    private static func arguments(pid: Int32, uid: UInt32) -> [String] {
        guard uid == getuid() || geteuid() == 0 else { return [] }
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var len = 0
        guard sysctl(&mib, 3, nil, &len, nil, 0) == 0, len > 0, len < 1 << 20 else { return [] }
        var buffer = [UInt8](repeating: 0, count: len)
        guard sysctl(&mib, 3, &buffer, &len, nil, 0) == 0 else { return [] }

        // Layout: int argc, then NUL-separated exec path, then NUL-separated argv.
        var cursor = 4
        var parts: [String] = []
        while cursor < len, parts.count < 64 {
            let slice = buffer[cursor..<len]
            if let end = slice.firstIndex(of: 0) {
                let text = String(decoding: slice[slice.startIndex..<end], as: UTF8.self)
                if !text.isEmpty { parts.append(text) }
                cursor += (slice.startIndex - buffer.startIndex) + end + 1
            } else {
                break
            }
            if parts.count == 1 { break }
        }
        return parts
    }

    /// Average CPU utilisation since process start, in percent of a single core.
    private static func cpuPercent(pid: Int32, elapsed: Double) -> Double {
        var info = proc_taskinfo()
        let size = MemoryLayout<proc_taskinfo>.stride
        guard proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, Int32(size)) == size else { return 0 }
        let nanos = info.pti_total_user &+ info.pti_total_system
        guard nanos > 0, elapsed > 0 else { return 0 }
        return Double(nanos) / 1_000_000_000.0 / elapsed * 100.0
    }

    private static func now() -> TimeInterval {
        var tv = timeval()
        gettimeofday(&tv, nil)
        return Double(tv.tv_sec) + Double(tv.tv_usec) / 1_000_000.0
    }

    private static func uptimeSeconds() -> TimeInterval {
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        var boot = timeval()
        var len = MemoryLayout<timeval>.size
        guard sysctl(&mib, 2, &boot, &len, nil, 0) == 0 else { return 0 }
        return now() - (Double(boot.tv_sec) + Double(boot.tv_usec) / 1_000_000.0)
    }

    public static func buildTree(_ processes: [ProcInfo]) -> [Int32: [ProcInfo]] {
        var tree: [Int32: [ProcInfo]] = [:]
        for proc in processes {
            tree[proc.ppid, default: []].append(proc)
        }
        return tree
    }

    /// Parses `lsof -F` field output into structured listening sockets.
    public static func listeningSockets() -> [ListeningSocket] {
        guard let lsof = Shell.which("lsof") else { return [] }
        let result = Shell.run(lsof, ["-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"], timeout: 30)
        guard result.status == 0 || !result.stdout.isEmpty else { return [] }

        var out: [ListeningSocket] = []
        var pid: Int32?
        var command = ""
        for line in result.stdout.split(separator: "\n") {
            guard let tag = line.first else { continue }
            let value = String(line.dropFirst())
            switch tag {
            case "p": pid = Int32(value)
            case "c": command = value
            case "n":
                guard let (address, port) = parseEndpoint(value) else { break }
                out.append(ListeningSocket(pid: pid, process: command, address: address, port: port))
            default: break
            }
        }
        return out
    }

    /// "127.0.0.1:8080", "*:22", "[::1]:631", "localhost:5432"
    private static func parseEndpoint(_ endpoint: String) -> (String, Int)? {
        if endpoint.hasPrefix("[") {
            guard let close = endpoint.firstIndex(of: "]") else { return nil }
            let host = String(endpoint[endpoint.index(after: endpoint.startIndex)..<close])
            let rest = endpoint[endpoint.index(after: close)...]
            guard rest.hasPrefix(":") else { return nil }
            return (host, Int(rest.dropFirst()) ?? -1)
        }
        guard let colon = endpoint.lastIndex(of: ":") else { return nil }
        let host = String(endpoint[endpoint.startIndex..<colon])
        let port = Int(endpoint[endpoint.index(after: colon)...]) ?? -1
        return (host, port)
    }

    /// Signals are only delivered when the pid still refers to the process we
    /// originally identified. PIDs recycle, so without the start-time check a
    /// kill issued a moment later can land on an unrelated process.
    private static func signalIfSameProcess(pid: Int32, expectedStart: Date?, sig: Int32) {
        if let expectedStart, let actual = startTime(ofPID: pid), actual != expectedStart {
            return
        }
        kill(pid, sig)
    }

    private static func startTime(ofPID pid: Int32) -> Date? {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return nil }
        let bootEpoch = now() - uptimeSeconds()
        return Date(timeIntervalSince1970: bootEpoch + Double(info.kp_proc.p_starttime.tv_sec))
    }

    public static func killTree(pid: Int32, timeout: TimeInterval = 3) -> Bool {
        let processes = allProcesses()
        let tree = buildTree(processes)
        var startTimes: [Int32: Date] = [:]
        for proc in processes {
            if let started = proc.startTime { startTimes[proc.pid] = started }
        }

        // Never signal pid 1 or our own process: a mis-resolved target must not
        // take down launchd or the scanner itself.
        var targets = [pid]
        var index = 0
        while index < targets.count {
            let current = targets[index]
            for child in tree[current] ?? [] where !targets.contains(child.pid) {
                targets.append(child.pid)
            }
            index += 1
        }
        targets = targets.filter { $0 > 1 && $0 != getpid() && $0 != getppid() }

        func signal(_ sig: Int32) {
            for target in targets.sorted(by: { $0 > $1 }) {
                signalIfSameProcess(pid: target, expectedStart: startTimes[target], sig: sig)
            }
        }

        signal(SIGTERM)
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if targets.allSatisfy({ kill($0, 0) != 0 }) { return true }
            usleep(120_000)
        }
        signal(SIGKILL)
        usleep(120_000)
        return targets.allSatisfy { kill($0, 0) != 0 }
    }
}
