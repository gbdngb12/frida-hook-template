import frida
import sys

pid = int(sys.argv[1])

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[!] Error: {message['stack']}")

module_name = "YES24eBook.exe"
target_offset = 0xd0c90

# -------- Frida Script --------
script_code = rf"""
// -------- Offset-based Hook --------
const base   = Process.getModuleByName("{module_name}").base;
const cbAddr = base.add({target_offset});    

Interceptor.attach(cbAddr, {{
    onEnter(args){{
        send("[offset] onEnter called");
    }},
    onLeave: function(retval) {{
        send("[offset] onLeave called, retval: " + retval);
    }}
}});
"""

# attach and load
session = frida.attach(pid)
script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()

