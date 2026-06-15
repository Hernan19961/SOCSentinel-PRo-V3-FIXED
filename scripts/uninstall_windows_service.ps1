schtasks /Delete /TN "SOCSentinel Backend" /F
schtasks /Delete /TN "SOCSentinel Agent" /F
Write-Output "Tareas SOCSentinel eliminadas."
