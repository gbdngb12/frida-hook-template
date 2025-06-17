import frida
import sys

pid = int(sys.argv[1])

def on_message(message, data):
    if message["type"] == "send":
        print(f"[+] {message['payload']}")
    elif message["type"] == "error":
        print(f"[!] {message['stack']}")

script_code = r"""
const base   = Process.getModuleByName("ksandbox.dll").base;
const target = base.add(0xA5D0);

function readPath(oa) {
    if (oa.isNull()) return "<NULL OA>";
    const objectName = oa
        .add(Process.pointerSize === 8 ? 0x10 : 0x08)
        .readPointer();
    if (objectName.isNull()) return "<NULL ObjectName>";

    const length  = objectName.readU16();
    const bufPtr  = objectName
        .add(Process.pointerSize === 8 ? 0x08 : 0x04)
        .readPointer();

    if (bufPtr.isNull() || length === 0) return "<EMPTY>";
    return bufPtr.readUtf16String(length / 2);
}

Interceptor.attach(target, {
    onEnter(args) {
        try {
            send(`[NtCreateFile] Path: ${readPath(args[3])}`);
        } catch (e) {
            send(`[NtCreateFile] Path read error: ${e}`);
        }
    },
    onLeave(retval) {
        send(`[NtCreateFile] Retval: 0x${retval.toString(16)}`);
    }
});
"""

session = frida.attach(pid)
script  = session.create_script(script_code)
script.on("message", on_message)
script.load()

sys.stdin.read()
