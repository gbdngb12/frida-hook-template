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
var symbol_addr = Module.getExportByName("target.dll", "func");
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

// -------- Offset-based Hook --------
// 예: target.dll + 0x1234 (offset은 16진수로 전달 가능)
var base = Process.getModuleByName("target.dll").base;
if (base !== null) {
    var offset = 0x1234;  // 여기에 원하는 오프셋 입력
    var target_addr = base.add(offset);
    Interceptor.attach(target_addr, {
        onEnter: function(args) {
            send("[offset] onEnter called at offset 0x1234");
        },
        onLeave: function(retval) {
            send("[offset] onLeave called, retval: " + retval);
        }
    });
} else {
    send("[offset] target.dll not found");
}
"""

# attach and load
session = frida.attach(pid)
script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()

