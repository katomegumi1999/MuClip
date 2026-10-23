<#
.SYNOPSIS
    两台 Windows 之间的纯 TCP 吞吐量测速脚本（零第三方依赖，支持局域网 IP 与端口映射/FRP 域名）

.EXAMPLE
    # 方式 1：直接双击或在 PowerShell 中无参运行（交互式菜单）
    .\tcp_speed_test.ps1

    # 方式 2：在接收端电脑（Server）运行
    .\tcp_speed_test.ps1 -Mode server -Port 42425

    # 方式 3：在发送端电脑（Client）运行（默认发送 512 MB 内存流）
    .\tcp_speed_test.ps1 -Mode client -Target 192.168.1.100 -Port 42425 -SizeMB 512
#>

param(
    [ValidateSet("", "server", "client")]
    [string]$Mode = "",

    [string]$Target = "127.0.0.1",

    [int]$Port = 42425,

    [int]$SizeMB = 512,

    [int]$ChunkKB = 128,

    [int]$SocketBufferMB = 0
)

$ErrorActionPreference = "Stop"

function Get-LocalIPv4List {
    try {
        return [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } |
            ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
            Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.Address.ToString() }
    } catch {
        return @()
    }
}

function Format-Speed([double]$bytesPerSec) {
    $mbps = $bytesPerSec / (1024.0 * 1024.0)
    $gbpsBit = ($bytesPerSec * 8.0) / 1000000.0
    return ("{0:N2} MB/s ({1:N1} Mbps)" -f $mbps, $gbpsBit)
}

if ([string]::IsNullOrWhiteSpace($Mode)) {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "         Windows 纯 TCP 局域网 / 端口映射 测速工具         " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    $ips = Get-LocalIPv4List
    if ($ips.Count -gt 0) {
        Write-Host ("本机局域网 IPv4: " + ($ips -join ", ")) -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  [1] 作为接收端 (Server) - 监听端口等待测速连接"
    Write-Host "  [2] 作为发送端 (Client) - 向目标 IP:端口 发起测速"
    Write-Host ""
    $choice = Read-Host "请选择模式 (输入 1 或 2)"
    if ($choice -eq "1") {
        $Mode = "server"
        $inputPort = Read-Host "请输入监听端口 (默认 $Port)"
        if (-not [string]::IsNullOrWhiteSpace($inputPort)) { $Port = [int]$inputPort }
    } else {
        $Mode = "client"
        $inputTarget = Read-Host "请输入对端 IP 或 域名:端口 (例如 192.168.1.100 或 frp.example.com:42425)"
        if (-not [string]::IsNullOrWhiteSpace($inputTarget)) { $Target = $inputTarget.Trim() }
        if ($Target -notmatch ":") {
            $inputPort = Read-Host "请输入对端端口 (默认 $Port)"
            if (-not [string]::IsNullOrWhiteSpace($inputPort)) { $Port = [int]$inputPort }
        }
        $inputSize = Read-Host "请输入测试数据大小 MB (默认 $SizeMB MB)"
        if (-not [string]::IsNullOrWhiteSpace($inputSize)) { $SizeMB = [int]$inputSize }
    }
}

# 允许 Target 直接写成 "host:port"
if ($Target -match "^(.+):(\d+)$") {
    $Target = $Matches[1]
    $Port = [int]$Matches[2]
}

$chunkSize = $ChunkKB * 1024
$socketBufBytes = $SocketBufferMB * 1024 * 1024

if ($Mode -eq "server") {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
    if ($socketBufBytes -gt 0) {
        $listener.Server.ReceiveBufferSize = $socketBufBytes
        $listener.Server.SendBufferSize = $socketBufBytes
    }
    $listener.Server.NoDelay = $true
    $listener.Start()

    $ips = Get-LocalIPv4List
    Write-Host ""
    Write-Host "[Server] 已启动纯 TCP 测速服务端，正在监听 0.0.0.0:$Port" -ForegroundColor Green
    if ($ips.Count -gt 0) {
        Write-Host ("[Server] 请在另一台电脑运行: .\tcp_speed_test.ps1 -Mode client -Target {0} -Port {1}" -f $ips[0], $Port) -ForegroundColor Yellow
    }
    Write-Host "[Server] 按 Ctrl+C 可随时退出..." -ForegroundColor DarkGray

    try {
        while ($true) {
            $client = $listener.AcceptTcpClient()
            if ($socketBufBytes -gt 0) {
                $client.ReceiveBufferSize = $socketBufBytes
                $client.SendBufferSize = $socketBufBytes
            }
            $client.NoDelay = $true

            $remoteEp = $client.Client.RemoteEndPoint.ToString()
            Write-Host "`n[Server] 收到来自 $remoteEp 的测速连接..." -ForegroundColor Cyan

            $stream = $client.GetStream()
            $buf = New-Object byte[] $chunkSize

            # 读取前 8 字节头部：预期总字节数 (Int64 Little-Endian)
            $header = New-Object byte[] 8
            $readHeader = 0
            while ($readHeader -lt 8) {
                $r = $stream.Read($header, $readHeader, 8 - $readHeader)
                if ($r -le 0) { break }
                $readHeader += $r
            }
            $expectedBytes = [System.BitConverter]::ToInt64($header, 0)

            $totalReceived = 0L
            $bytesSinceLast = 0L
            $peakBps = 0.0
            $swTotal = [System.Diagnostics.Stopwatch]::StartNew()
            $swInterval = [System.Diagnostics.Stopwatch]::StartNew()

            while ($totalReceived -lt $expectedBytes) {
                $toRead = [Math]::Min($buf.Length, $expectedBytes - $totalReceived)
                $n = $stream.Read($buf, 0, [int]$toRead)
                if ($n -le 0) { break }

                $totalReceived += $n
                $bytesSinceLast += $n

                if ($swInterval.ElapsedMilliseconds -ge 250 -or $totalReceived -eq $expectedBytes) {
                    $sec = $swInterval.Elapsed.TotalSeconds
                    $instBps = if ($sec -gt 0) { $bytesSinceLast / $sec } else { 0.0 }
                    if ($instBps -gt $peakBps) { $peakBps = $instBps }

                    $pct = if ($expectedBytes -gt 0) { ($totalReceived * 100.0) / $expectedBytes } else { 100.0 }
                    Write-Host ("`r[接收中] {0,6:N1}% | {1,7:N1} / {2:N1} MB | 瞬时: {3}   " -f `
                        $pct, ($totalReceived / 1MB), ($expectedBytes / 1MB), (Format-Speed $instBps)) -NoNewline

                    $bytesSinceLast = 0L
                    $swInterval.Restart()
                }
            }

            $swTotal.Stop()
            # 回传 2 字节 "OK" 确认对端已完成全部接收
            $ack = [System.Text.Encoding]::ASCII.GetBytes("OK")
            $stream.Write($ack, 0, $ack.Length)
            $stream.Flush()
            $client.Close()

            $totalSec = [Math]::Max($swTotal.Elapsed.TotalSeconds, 0.001)
            $avgBps = $totalReceived / $totalSec

            Write-Host ""
            Write-Host "----------------------------------------------------------" -ForegroundColor Green
            Write-Host ("[Server] 测速完成! 对端: $remoteEp") -ForegroundColor Green
            Write-Host ("  总接收数据 : {0:N2} MB ({1:N0} Bytes)" -f ($totalReceived / 1MB), $totalReceived)
            Write-Host ("  总耗时     : {0:N2} 秒" -f $totalSec)
            Write-Host ("  平均吞吐量 : {0}" -f (Format-Speed $avgBps)) -ForegroundColor Yellow
            Write-Host ("  峰值吞吐量 : {0}" -f (Format-Speed $peakBps)) -ForegroundColor Cyan
            Write-Host "----------------------------------------------------------" -ForegroundColor Green
        }
    } finally {
        $listener.Stop()
    }
}
else {
    $totalBytes = [int64]$SizeMB * 1024L * 1024L
    $bufModeText = if ($socketBufBytes -gt 0) { "$SocketBufferMB MB" } else { "OS Auto-Tuning" }
    Write-Host ""
    Write-Host ("[Client] 正在连接目标 {0}:{1} (测试数据量: {2} MB, 分块: {3} KB, Socket 缓冲区: {4})..." -f `
        $Target, $Port, $SizeMB, $ChunkKB, $bufModeText) -ForegroundColor Cyan

    $swConnect = [System.Diagnostics.Stopwatch]::StartNew()
    $client = [System.Net.Sockets.TcpClient]::new()
    if ($socketBufBytes -gt 0) {
        $client.ReceiveBufferSize = $socketBufBytes
        $client.SendBufferSize = $socketBufBytes
    }
    $client.NoDelay = $true
    $client.Connect($Target, $Port)
    $swConnect.Stop()

    Write-Host ("[Client] TCP 握手成功! 连接延迟: {0:N2} ms" -f $swConnect.Elapsed.TotalMilliseconds) -ForegroundColor Green

    $stream = $client.GetStream()
    $buf = New-Object byte[] $chunkSize
    [System.Random]::new(42).NextBytes($buf)

    # 先发送 8 字节总长度头部
    $header = [System.BitConverter]::GetBytes($totalBytes)
    $stream.Write($header, 0, 8)

    $sentBytes = 0L
    $bytesSinceLast = 0L
    $peakBps = 0.0
    $swTotal = [System.Diagnostics.Stopwatch]::StartNew()
    $swInterval = [System.Diagnostics.Stopwatch]::StartNew()

    while ($sentBytes -lt $totalBytes) {
        $toSend = [Math]::Min($buf.Length, $totalBytes - $sentBytes)
        $stream.Write($buf, 0, [int]$toSend)

        $sentBytes += $toSend
        $bytesSinceLast += $toSend

        if ($swInterval.ElapsedMilliseconds -ge 250 -or $sentBytes -eq $totalBytes) {
            $sec = $swInterval.Elapsed.TotalSeconds
            $instBps = if ($sec -gt 0) { $bytesSinceLast / $sec } else { 0.0 }
            if ($instBps -gt $peakBps) { $peakBps = $instBps }

            $pct = ($sentBytes * 100.0) / $totalBytes
            Write-Host ("`r[发送中] {0,6:N1}% | {1,7:N1} / {2:N1} MB | 瞬时: {3}   " -f `
                $pct, ($sentBytes / 1MB), ($totalBytes / 1MB), (Format-Speed $instBps)) -NoNewline

            $bytesSinceLast = 0L
            $swInterval.Restart()
        }
    }

    $stream.Flush()

    # 等待对端接收完毕并返回 2 字节 "OK"，以测算真实端到端落地速度（不含发送缓冲区虚标）
    $ack = New-Object byte[] 2
    $readAck = 0
    while ($readAck -lt 2) {
        $r = $stream.Read($ack, $readAck, 2 - $readAck)
        if ($r -le 0) { break }
        $readAck += $r
    }

    $swTotal.Stop()
    $client.Close()

    $totalSec = [Math]::Max($swTotal.Elapsed.TotalSeconds, 0.001)
    $avgBps = $sentBytes / $totalSec

    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host "                纯 TCP 端到端测速结果报告                 " -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host ("  目标地址   : {0}:{1}" -f $Target, $Port)
    Write-Host ("  握手延迟   : {0:N2} ms" -f $swConnect.Elapsed.TotalMilliseconds)
    Write-Host ("  传输数据量 : {0:N2} MB ({1:N0} Bytes)" -f ($sentBytes / 1MB), $sentBytes)
    Write-Host ("  总耗时     : {0:N2} 秒 (含接收端完整确认)" -f $totalSec)
    Write-Host ("  平均速度   : {0}" -f (Format-Speed $avgBps)) -ForegroundColor Yellow
    Write-Host ("  峰值速度   : {0}" -f (Format-Speed $peakBps)) -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Green
}
