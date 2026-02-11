# Detection: Encoded PowerShell Execution

**Objective:** Detect obfuscated PowerShell commands using Sysmon.

**Simulated Attack:** Encoded PowerShell command using `-enc`.

**Log Source:** Sysmon Event ID 1 (Process Creation)

**Detection Logic:**
- EventID = 1
- Image ends with "powershell.exe"
- CommandLine contains "-enc"

**Example Observation:**
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- CommandLine: powershell.exe -enc SQBuAHYAbwBrAGUALQBDAG8AbQBtAGEAbgBkACAAIgB3AGgAbwBhAG0AaQAiAA==
- ParentImage: explorer.exe

**Why This Matters:**  
Attackers use encoded commands to evade simple detections.

**Limitations:**  
Some administrators may use encoded PowerShell for legitimate tasks.

**References:**  
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)  
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
