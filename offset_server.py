import frida
import sys

# 원격 기기 IP 주소
REMOTE_IP = "192.168.4.1"
# 대상 프로세스 ID (실행 중인 PID를 입력하세요)
# charx-s+   769     1  0 Jan11 ?        00:04:06 /usr/sbin/CharxSystemConfigManager

try:
    pid = int(sys.argv[1])
except:
    print("Usage: python script.py <PID>")
    sys.exit(1)

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[!] Error: {message['stack']}")

module_name = "mqtt_publisher.so"
target_offset = 0xA56A

# 1. 원격 기기 연결 설정
try:
    # 네트워크를 통해 원격 Frida 서버에 접속
    device = frida.get_device_manager().add_remote_device(REMOTE_IP)
    print(f"[*] Connected to {REMOTE_IP}")
    
    # 2. 원격 기기의 프로세스에 attach
    session = device.attach(pid)
    
    # -------- Frida Script --------
    script_code = rf"""
    console.log("[*] Script attached. Searching for Python symbols...");

    // 1. [수정됨] findExportByName(null, ...) 대신 findGlobalExportByName 사용
    // 이 함수는 로드된 모든 라이브러리에서 심볼을 찾습니다.
    var addrPyObject_Str = null;
    var addrPyUnicode_AsUTF8 = null;

    try {{
        addrPyObject_Str = Module.findGlobalExportByName("PyObject_Str");
        addrPyUnicode_AsUTF8 = Module.findGlobalExportByName("PyUnicode_AsUTF8");
        
        // Python 2 호환성 체크
        if (addrPyUnicode_AsUTF8 === null) {{
            addrPyUnicode_AsUTF8 = Module.findGlobalExportByName("PyString_AsString");
        }}
    }} catch (e) {{
        console.log("[!] Error finding exports: " + e);
    }}

    if (addrPyObject_Str !== null && addrPyUnicode_AsUTF8 !== null) {{
        console.log("[*] Symbols found!");
        console.log("    PyObject_Str: " + addrPyObject_Str);
        console.log("    PyUnicode_AsUTF8: " + addrPyUnicode_AsUTF8);

        // NativeFunction 생성
        var PyObject_Str = new NativeFunction(addrPyObject_Str, 'pointer', ['pointer']);
        var PyUnicode_AsUTF8 = new NativeFunction(addrPyUnicode_AsUTF8, 'pointer', ['pointer']);

        // 헬퍼 함수 정의
        function inspectPyObject(objAddr) {{
            try {{
                var ptrObj = ptr(objAddr);
                if (ptrObj.isNull()) return "NULL";

                // PyObject_Str 호출 (str(obj)와 동일)
                var strObj = PyObject_Str(ptrObj);
                if (strObj.isNull()) return "PyObject_Str returned NULL";

                // UTF8 문자열 포인터 추출
                var cStrPtr = PyUnicode_AsUTF8(strObj);
                if (cStrPtr.isNull()) return "PyUnicode_AsUTF8 returned NULL";

                return cStrPtr.readUtf8String();
            }} catch (e) {{
                return "Error: " + e;
            }}
        }}

        const base   = Process.getModuleByName("{module_name}").base;
        //const cbAddr = base.add({target_offset});    
        const cbAddr = base.add({target_offset}).or(1); // For Thumb Mode
        console.log("Base: " + base);
        console.log("Target Address: " + cbAddr);

        Interceptor.attach(cbAddr, {{
            onEnter(args){{
                send("[offset] onEnter called");
                var r0_val = this.context.r0;
                var r0_str = inspectPyObject(r0_val);

                send("========================================");
                send("[Register r0] Address: " + r0_val);
                send("[Register r0] String : " + r0_str);
            }},
            onLeave: function(retval) {{
                send("[offset] onLeave called, retval: " + retval);
            }}
        }});
    }}



    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to stop.")
    sys.stdin.read()

except Exception as e:
    print(f"[!] Exception: {e}")