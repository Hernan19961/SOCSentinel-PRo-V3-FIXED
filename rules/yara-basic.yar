rule SOCSentinel_Suspicious_Script_Dropper
{
  meta:
    description = "Basic portfolio YARA rule for suspicious script droppers"
    mitre = "T1059"
  strings:
    $ps1 = "powershell" nocase
    $iex = "iex" nocase
    $download = "DownloadString" nocase
    $wscript = "WScript.Shell" nocase
  condition:
    2 of them
}
