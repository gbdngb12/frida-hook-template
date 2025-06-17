import frida
import sys

pid = int(sys.argv[1])

def on_message(message, data):
    print(f"[{message}] => {data}")

# -------- Frida Script --------
script_code = r"""
var setdec_hook = Module.findExportByName("target.dll", "func");
Interceptor.attach(setdec_hook, {
	onEnter: function(args) {
	
	},
	onLeave: function(retval) {
	
	}
});
"""

session = frida.attach(pid)
script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
