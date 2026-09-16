@echo off
setlocal
chcp 65001 >nul
set "TRIDENT_TUNNEL_FILE=%~f0"
powershell.exe -NoLogo -NoProfile -Command "$text=[IO.File]::ReadAllText($env:TRIDENT_TUNNEL_FILE,[Text.Encoding]::UTF8); $parts=[regex]::Split($text,'(?m)^# TRIDENT_POWERSHELL_START\r?$'); if($parts.Count -ne 2){throw 'Invalid launcher file'}; & ([scriptblock]::Create($parts[1]))"
set "TRIDENT_TUNNEL_EXIT=%errorlevel%"
echo.
pause
exit /b %TRIDENT_TUNNEL_EXIT%
# TRIDENT_POWERSHELL_START
# Один переносимый BAT: PowerShell-код хранится в этом же файле.
# Пароль и подтверждение ключа хоста обрабатывает только штатный OpenSSH.
$ErrorActionPreference = 'Stop'
$sshProcess = $null
$exitCode = 0

try {
    Write-Host 'TRIDENT - открыть панель на VPS' -ForegroundColor Green
    Write-Host 'Установщик на сервере должен завершиться. Это окно держит SSH-туннель.'
    Write-Host ''

    $sshPath = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
    if (-not (Test-Path -LiteralPath $sshPath -PathType Leaf)) {
        $sshCommand = Get-Command ssh.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $sshCommand) { throw 'Не найден OpenSSH Client. Добавьте его в дополнительных компонентах Windows и повторите запуск.' }
        $sshPath = $sshCommand.Source
    }

    $serverAddress = (Read-Host 'IP или домен VPS (без http:// и порта)').Trim()
    $parsedAddress = $null
    $validIp = [Net.IPAddress]::TryParse($serverAddress, [ref]$parsedAddress)
    $validDomain = $serverAddress.Length -le 253 -and $serverAddress -match '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$'
    if (-not ($validIp -or $validDomain) -or $serverAddress -match '[\s%]') {
        throw 'Нужен IP или домен без пробелов, URL и SSH-порта. IPv6 вводите без квадратных скобок.'
    }
    $loginName = (Read-Host 'SSH-логин [root]').Trim()
    if (-not $loginName) { $loginName = 'root' }
    if ($loginName -notmatch '^[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?$') { throw 'Некорректный SSH-логин.' }
    $portText = (Read-Host 'SSH-порт [22]').Trim()
    if (-not $portText) { $portText = '22' }
    $sshPort = 0
    if ($portText -notmatch '^\d{1,5}$' -or -not [int]::TryParse($portText, [ref]$sshPort) -or $sshPort -lt 1 -or $sshPort -gt 65535) {
        throw 'SSH-порт должен быть целым числом от 1 до 65535.'
    }

    # Локальный порт отличается от backend VPS, чтобы не мешать локальной панели.
    # Если 18787 занят, ОС выбирает свободный порт; чужие процессы не останавливаем.
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 18787)
    try {
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start()
    } catch {
        $listener.Stop()
        $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start()
    }
    $localPort = $listener.LocalEndpoint.Port
    $listener.Stop()
    $panelUrl = "http://127.0.0.1:$localPort"
    Write-Host ''
    Write-Host "Подключение к $serverAddress, SSH-порт $sshPort. Панель: $panelUrl"
    Write-Host 'OpenSSH может запросить подтверждение ключа сервера и пароль. При вводе пароля символы не отображаются.'
    Write-Host 'После успешного подключения браузер откроется автоматически. Для отключения закройте это окно.'
    Write-Host ''

    # Значения проверены выше и передаются как аргументы процесса, без cmd /c.
    # Не разрешаем SSH слушать LAN-интерфейсы. Сохраняем штатную проверку host key.
    $sshArguments = @('-N', '-T', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3', '-o', 'ConnectTimeout=20', '-p', "$sshPort", '-l', $loginName,
        '-L', "127.0.0.1:${localPort}:127.0.0.1:8787", '--', $serverAddress)
    $sshProcess = Start-Process -FilePath $sshPath -ArgumentList $sshArguments -NoNewWindow -PassThru
    $ready = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(180)
    while ([DateTime]::UtcNow -lt $deadline) {
        $sshProcess.Refresh()
        if ($sshProcess.HasExited) { throw 'SSH завершился. Проверьте сообщение выше: IP, порт, логин, пароль или SSH-ключ.' }
        try {
            # Обращение только к своему loopback, без системного HTTP proxy.
            $request = [Net.HttpWebRequest]::Create("$panelUrl/healthz")
            $request.Proxy = $null
            $request.Timeout = 1000
            $request.ReadWriteTimeout = 1000
            $response = $request.GetResponse()
            try {
                $reader = New-Object IO.StreamReader($response.GetResponseStream())
                try { $health = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
                if ($health.status -eq 'ok') { $ready = $true; break }
            } finally { $response.Dispose() }
        } catch { }
        Start-Sleep -Milliseconds 700
    }
    if (-not $ready) { throw 'Панель не ответила за 3 минуты. Проверьте на VPS: sudo systemctl status trident-panel' }
    $sshProcess.Refresh()
    if ($sshProcess.HasExited) { throw 'SSH завершился до открытия браузера. Проверьте сообщение SSH выше.' }
    Write-Host "Панель доступна: $panelUrl" -ForegroundColor Green
    Start-Process $panelUrl
    # Короткие ожидания дают PowerShell обработать Ctrl+C и выполнить finally.
    while (-not $sshProcess.WaitForExit(500)) { }
    if ($sshProcess.ExitCode -ne 0) { throw 'SSH-соединение прервано. Для подключения запустите этот BAT снова.' }
} catch {
    Write-Host ''
    Write-Host $_.Exception.Message -ForegroundColor Red
    $exitCode = 1
} finally {
    # Закрываем только процесс, созданный этим запуском, а не все SSH-сеансы.
    if ($null -ne $sshProcess) {
        if (-not $sshProcess.HasExited) { $sshProcess.Kill(); $sshProcess.WaitForExit() }
        $sshProcess.Dispose()
    }
}
exit $exitCode
