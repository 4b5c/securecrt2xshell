import os
import re
import subprocess
from securecrt_cipher import SecureCRTCryptoV2
from XmanagerCrypto import XShellCrypto
from pprint import pprint


class SecureCRTINI:
    def parse(self, inifile):
        return self.get_info_from_securecrt(inifile)

    def dec_securecrt_password(self, rawpassword):
        rawpassword = rawpassword[3:]
        cipher = SecureCRTCryptoV2()
        return cipher.decrypt(rawpassword, prefix="02")

    def get_info_from_securecrt(self, file):
        info = {}
        with open(file, encoding="utf-8-sig") as f:
            for line in f:
                fields = line.split("=")
                k = fields[0]
                v = fields[1] if len(fields) == 2 else ""
                info[k] = v.strip()

            out = {}
            protocol = info['S:"Protocol Name"']

            portKey = 'D:"[SSH2] Port"' if protocol == "SSH2" else 'D:"Port"'

            port = str(int(info[portKey], 16))
            hostname = info['S:"Hostname"']
            username = info['S:"Username"']

        password = ""
        rawpassword = info['S:"Password V2"']
        if rawpassword:
            password = self.dec_securecrt_password(rawpassword)
        out["Protocol"] = protocol
        out["Hostname"] = hostname
        out["Username"] = username
        out["Port"] = port
        out["Password"] = password

        return out


class XshellXsh:
    xshell_template = """
[CONNECTION:PROXY]
Proxy=
StartUp=0
[CONNECTION:SERIAL]
BaudRate=12
StopBits=0
FlowCtrl=0
Parity=0
DataBits=3
ComPort=0
[SessionInfo]
Version=7.1
Description=Xshell session file
[TRACE]
SockConn=1
SshLogin=0
SshTunneling=0
SshPacket=0
TelnetOptNego=0
[CONNECTION:SSH]
KeyExchange=
SSHCiphers=chacha20-poly1305@openssh.com:1,aes128-ctr:1,aes192-ctr:1,aes256-ctr:1,aes128-gcm@openssh.com:1,aes256-gcm@openssh.com:1,aes128-cbc:1,aes192-cbc:1,aes256-cbc:1,3des-cbc:1,blowfish-cbc:1,cast128-cbc:1,arcfour:1,rijndael128-cbc:1,rijndael192-cbc:1,rijndael256-cbc:1,rijndael-cbc@lysator.liu.se:1,arcfour128:1,arcfour256:1
AgentForwarding=0
ForwardToXmanager=1
Compression=0
NoTerminal=0
UseAuthAgent=0
MAC=
SSHMACs=hmac-sha2-256-etm@openssh.com:1,hmac-sha2-512-etm@openssh.com:1,hmac-sha1-etm@openssh.com:1,hmac-sha2-256:1,hmac-sha2-512:1,hmac-sha1:1,hmac-sha1-96:1,hmac-md5:1,hmac-md5-96:1,hmac-ripemd160:1,hmac-ripemd160@openssh.com:1,umac-64@openssh.com:1,umac-128@openssh.com:1,hmac-sha1-96-etm@openssh.com:1,hmac-md5-etm@openssh.com:1,hmac-md5-96-etm@openssh.com:1,umac-64-etm@openssh.com:1,umac-128-etm@openssh.com:1
InitRemoteDirectory=
ForwardX11=1
VexMode=2
Cipher=
Display=localhost:0.0
FwdReqCount=0
InitLocalDirectory=
NoConnFileManager=1
SSHKeyExchanges=curve25519-sha256@libssh.org:1,curve25519-sha256:1,ecdh-sha2-nistp256:1,ecdh-sha2-nistp384:1,ecdh-sha2-nistp521:1,diffie-hellman-group-exchange-sha256:1,diffie-hellman-group-exchange-sha1:1,diffie-hellman-group18-sha512:1,diffie-hellman-group16-sha512:1,diffie-hellman-group14-sha256:1,diffie-hellman-group14-sha1:1,diffie-hellman-group1-sha1:1
RemoteCommand=
SaveHostKey=0
[BELL]
FilePath=
RepeatTime=3
FlashWindow=0
BellMode=1
IgnoreTime=3
[USERINTERFACE]
NoQuickButton=0
QuickCommand=
[CONNECTION:FTP]
Passive=1
InitRemoteDirectory=
InitLocalDirectory=
[TRANSFER]
FolderMethod=0
DropXferHandler=2
XmodemUploadCmd=rx
ZmodemUploadCmd=rz -E
FolderPath=
YmodemUploadCmd=rb -E
AutoZmodem=1
SendFolderPath=
DuplMethod=0
XYMODEM_1K=0
[CONNECTION]
Port={Port}
Protocol={Protocol}
Host={Hostname}
AutoReconnect=0
AutoReconnectLimit=0
Description=
AutoReconnectInterval=30
UseNaglesAlgorithm=0
FtpPort=21
IPV=0
[CONNECTION:HWCERTIFICATES]
Count=0
[TERMINAL]
Rows=24
CtrlAltIsAltGr=1
InitOriginMode=0
InitReverseMode=0
DisableBlinkingText=0
CodePage=65001
InitAutoWrapMode=1
Cols=80
InitEchoMode=0
Type=xterm
DisableAlternateScreen=0
CJKAmbiAsWide=0
ScrollBottomOnKeyPress=0
PauseScrollBottom=0
DisableTitleChange=0
ForceEraseOnDEL=0
InitInsertMode=0
ShiftForcesLocalUseOfMouse=1
FontLineCharacter=1
ScrollbackSize=10240
NewLineRecv=2
InitCursorMode=0
FixedCols=0
NewLineSend=0
BackspaceSends=2
UseInitSize=0
UseLAltAsMeta=0
UseRAltAsMeta=0
AltKeyMapPath=
DeleteSends=0
DisableTermPrinting=0
IgnoreResizeRequest=1
UseAppMouse=1
ScrollBottomOnTermOutput=1
FontPowerLine=1
ScrollErasedText=1
KeyMap=0
MoveToWorkFolder=1
EraseWithBackgroundColor=1
InitNewlineMode=0
InitKeypadMode=0
TerminalNameForEcho=
[TERMINAL:WINDOW]
ColorScheme=XTerm
FontQuality=0
LineSpace=0
CursorColor=65280
CursorBlinkInterval=600
TabColorType=0
FontStyle=0
CursorAppearance=0
TabColorOther=0
FontSize=9
AsianFontSize=9
CursorBlink=0
BGImageFile=
BoldMethod=2
CursorTextColor=0
BGImagePos=0
AsianFont=DejaVu Sans Mono
FontFace=DejaVu Sans Mono
CharSpace=0
AsianFontStyle=0
MarginBottom=5
MarginLeft=5
MarginTop=5
MarginRight=5
[CONNECTION:TELNET]
XdispLoc=1
NegoMode=0
CharMode=0
Display=$PCADDR:0.0
[HIGHLIGHT]
HighlightSet=None
[CONNECTION:AUTHENTICATION]
Pkcs11Pin=
Library=0
Passphrase=
Pkcs11Middleware=
Delegation=0
UseInitScript=0
CapiPin=
TelnetLoginPrompt=ogin:
Password={Password}
RloginPasswordPrompt=assword:
UseExpectSend=0
TelnetPasswordPrompt=assword:
CapiKey=
ExpectSend_Count=0
AuthMethodList=01
ScriptPath=
UserKey=
UserName={Username}
[LOGGING]
FilePath=%n_%Y-%m-%d_%t.log
Overwrite=1
WriteFileTimestamp=0
Encoding=2
TimestampFormat=[%a] 
TermCode=0
AutoStart=0
Prompt=0
WriteTermTimestamp=0
[ADVANCED]
WaitPrompt=
PromptMax=0
SendLineDelayType=0
ApplyAllChanges=1
SendLineDelayInterval=0
SendCharDelayInterval=0
[CONNECTION:RLOGIN]
TermSpeed=38400
[CONNECTION:KEEPALIVE]
SendKeepAliveInterval=60
KeepAliveInterval=60
TCPKeepAlive=0
KeepAliveString=
SendKeepAlive=0
KeepAlive=1


"""

    def __init__(self, user, sid, masterpassword=None):
        ver = "7.0"

        self.cipher = XShellCrypto(
            SessionFileVersion=ver,
            UserName=user,
            SID=sid,
            MasterPassword=masterpassword,
        )

    def generate(self, info):
        info["Password"] = self.enc(info["Password"])
        return self.xshell_template.format(**info)

    def enc(self, text):
        enc = self.cipher.EncryptString(text)
        return enc


def get_win_username_sid():
    # 执行 whoami /user 命令
    result = subprocess.check_output(["whoami", "/user"]).decode("gb2312")

    for line in result.split("\n"):
        if "S-" in line:
            break

    # 使用正则表达式匹配用户名和SID
    pattern = r"[^\\]+\\(?P<username>\S+) (?P<sid>\S+)"
    match = re.search(pattern, result, re.IGNORECASE)

    if match:
        username = match.group("username")
        sid = match.group("sid")
        return username, sid
    else:
        return None, None


import codecs


def main():
    user, sid = get_win_username_sid()
    secureINI = SecureCRTINI()
    xshellXSH = XshellXsh(user, sid)

    securecrt_session_dir = (
        r"C:\Users\{user}\AppData\Roaming\VanDyke\Config\Sessions".format(user=user)
    )
    xshell_session_dir = (
        r"C:\Users\{user}\Documents\NetSarang Computer\7\Xshell\Sessions".format(
            user=user
        )
    )

    for root, dirs, files in os.walk(securecrt_session_dir):
        for d in dirs:
            xshell_dir = os.path.join(xshell_session_dir, d)
            os.makedirs(xshell_dir, exist_ok=True)
        for f in files:
            if "__FolderData__" in f:
                continue
            securecrt_ini_file = os.path.join(root, f)
            relpath = os.path.relpath(root, securecrt_session_dir)
            xshell_xsh_file = os.path.join(
                xshell_session_dir, relpath, f.replace(".ini", ".xsh")
            )

            info = secureINI.parse(securecrt_ini_file)
            data = xshellXSH.generate(info)
            with open(xshell_xsh_file, "w", encoding="utf-16le") as f:
                f.write("\ufeff")
                f.write(data)
            print("done..", xshell_xsh_file)


if __name__ == "__main__":
    main()
