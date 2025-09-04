import frida
import sys

pid = int(sys.argv[1])

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[!] Error: {message['stack']}")

# -------- Frida Script --------
script_code = r"""
// -------- Symbol-based Hook --------
var symbol_addr = Process.getModuleByName('ezPDFBookLib.dll').getExportByName('EZPDF_SetUnDrmEventHandler');
if (symbol_addr !== null) {
    Interceptor.attach(symbol_addr, {
        onEnter: function(args) {
            send("[symbol] onEnter called");
        },
        onLeave: function(retval) {
            send("[symbol] onLeave called, retval: " + retval);
        }
    });
} else {
    send("[symbol] func not found in target.dll");
}
"""

# attach and load
session = frida.attach(pid)
script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()