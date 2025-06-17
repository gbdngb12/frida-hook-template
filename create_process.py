#!/usr/bin/env python3
# 사용법: python hook_user_process.py <PID>

import frida, sys

if len(sys.argv) != 2:
    print(f"사용법: {sys.argv[0]} <PID>")
    sys.exit(1)

pid = int(sys.argv[1])

def on_message(message, data):
    if message["type"] == "send":
        print(f"[+] {message['payload']}")
    elif message["type"] == "error":
        print(f"[!] {message['stack']}")

js_code = r"""
const base   = Process.getModuleByName("ksandbox.dll").base;
const target = base.add(0xCA40);           // NtCreateUserProcess_Hook 오프셋

/*  a10 구조체에서 경로 추출
     - 32 bit: Length @ +0x38, Buffer @ +0x3C
     - 64 bit: Length @ +0x70, Buffer @ +0x78   */
const lenOffset = (Process.pointerSize === 8) ? 0x70 : 0x38;
const bufOffset = (Process.pointerSize === 8) ? 0x78 : 0x3C;

function getProcessPath(paramPtr) {
    if (paramPtr.isNull()) return "<NULL param>";
    const lengthBytes = paramPtr.add(lenOffset).readU16();   // BYTE 단위 길이
    const bufferPtr   = paramPtr.add(bufOffset).readPointer();
    if (bufferPtr.isNull() || lengthBytes === 0) return "<EMPTY>";
    return bufferPtr.readUtf16String(lengthBytes / 2);
}

Interceptor.attach(target, {
    /* 파라미터 인덱스
       0:a1 1:a2 2:a3 3:a4 4:a5 5:a6 6:a7 7:a8 8:a9 9:a10 10:a11 11:a12 */
    onEnter(args) {
        try {
            const procPath = getProcessPath(args[9]);
            send(`[NtCreateUserProcess] path = ${procPath}`);
        } catch (err) {
            send(`[NtCreateUserProcess] 경로 읽기 실패: ${err}`);
        }
    },
    onLeave(retval) {
        send(`[NtCreateUserProcess] retval = 0x${retval.toString(16)}`);
    }
});
"""

session = frida.attach(pid)
script  = session.create_script(js_code)
script.on("message", on_message)
script.load()

print("[*] 후킹 완료. Ctrl-C 로 종료합니다.")
sys.stdin.read()
