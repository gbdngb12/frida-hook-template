import frida
import sys

if len(sys.argv) < 2:
    print("사용법: python hook.py <PID>")
    sys.exit(1)

pid = int(sys.argv[1])

# 기준 모듈과 오프셋 정보
module_name = "mstscax.dll"
offset = 0x4734C0  # target address = base + offset

# 메시지 핸들러
def on_message(message, data):
    if message["type"] == "send":
        print(f"[+] {message['payload']}")
    elif message["type"] == "error":
        print(f"[!] {message['stack']}")

# Frida JS 코드
script_code = f"""
var base = Module.findBaseAddress("{module_name}");
if (base === null) {{
    send("[-] {module_name} not found.");
}} else {{
    var targetAddr = base.add(0x{offset:X});
    send("[*] {module_name} base: " + base);
    send("[*] Hooking targetAddr: " + targetAddr);

    Interceptor.attach(targetAddr, {{
        onEnter: function(args) {{
            send("[HOOK] onEnter at " + targetAddr);
            send("    RCX: " + this.context.rcx);
            send("    RDX: " + this.context.rdx);
        }},
        onLeave: function(retval) {{
            send("[HOOK] onLeave, retval: " + retval);
        }}
    }});
}}
"""

# attach 및 script 로드
session = frida.attach(pid)
script = session.create_script(script_code)
script.on("message", on_message)
script.load()

sys.stdin.read()

