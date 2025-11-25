import sys
import os
import tty
import termios
import time
import atexit
import shutil
import select
from collections import deque

# --- CONFIGURATION ---

LOG_FILE = "protocol_test_log.txt"

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'

# Kitty: Force Set flags=31 (Disambiguate|EventTypes|Alternates|AllKeys|Text)
KITTY_ENABLE = b'\x1b[=31;1u'
KITTY_DISABLE = b'\x1b[=0;1u'

# Win32: Enable ConPTY Input Mode
WIN32_ENABLE = b'\x1b[?9001h'
WIN32_DISABLE = b'\x1b[?9001l'

# PUA Range for Modifiers in Kitty (LeftShift ... IsoLevel5)
KITTY_MOD_KEYS_RANGE = range(57441, 57455)

# --- HELPERS ---

def write_screen(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()

def log_to_file(msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        timestamp = time.strftime("[%H:%M:%S] ")
        f.write(timestamp + msg + "\n")

def get_terminal_height():
    try:
        return shutil.get_terminal_size((80, 24)).lines
    except:
        return 24

def decode_utf8_safe(b):
    return b.decode('utf-8', errors='replace').replace('\x1b', 'ESC')

# --- PARSERS ---

class InputEvent:
    def __init__(self, raw, protocol, params, is_release, desc):
        self.raw = raw
        self.protocol = protocol
        self.params = params
        self.is_release = is_release
        self.desc = desc

    def __str__(self):
        return f"{self.protocol:<6} {self.desc:<30} | {self.params}"

def parse_kitty(raw):
    # Form 1: CSI key:alt ; mods:type ; text u
    # Form 2: CSI 1 ; mods:type [ABCDEFH...] (Functional)

    decoded = decode_utf8_safe(raw)

    # Basic check
    if not decoded.startswith('ESC['):
         return InputEvent(raw, "RAW", {}, False, repr(decoded))

    # Determine Terminator
    terminator = decoded[-1]
    content = decoded[4:-1] # strip ESC[ and terminator

    # Defaults
    all_codes = [0]
    modifiers = 1
    event_type = 1

    groups = content.split(';')

    # === STRATEGY 1: UNICODE MODE (ends in 'u') ===
    if terminator == 'u':
        try:
            if groups and groups[0]:
                code_strs = groups[0].split(':')
                all_codes = [int(x) for x in code_strs if x]

            if len(groups) > 1 and groups[1]:
                mod_subs = groups[1].split(':')
                modifiers = int(mod_subs[0] or 1)
                if len(mod_subs) > 1:
                    event_type = int(mod_subs[1])
        except ValueError:
            return InputEvent(raw, "ERR", {}, False, "Parse Error U")

    # === STRATEGY 2: FUNCTIONAL KEYS (ends in A-Z, ~) ===
    # Example: ESC[1;1:3D (Left Release)
    else:
        # Map letters back to Kitty PUA codes for unified testing
        # Up=A, Down=B, Right=C, Left=D, Home=H, End=F
        # F1=P, F2=Q, F3=R, F4=S
        func_map = {
            'A': 57373, 'B': 57374, 'C': 57375, 'D': 57376,
            'H': 57377, 'F': 57378,
            'P': 57381, 'Q': 57382, 'R': 57383, 'S': 57384
        }

        # Tilde mapping (PageUp=5~, etc) needs checking the first number
        tilde_map = {
            '5': 57379, '6': 57380, '2': 2, '3': 3, # Ins, Del
            '11': 57381, '12': 57382, '13': 57383, '14': 57384, # F1-F4 alt
            '15': 57385, '17': 57386, '18': 57387, '19': 57388, # F5-F8
            '20': 57389, '21': 57390, '23': 57391, '24': 57392  # F9-F12
        }

        # Determine Code
        code = 0
        if terminator in func_map:
            code = func_map[terminator]
        elif terminator == '~' and groups:
            # First group is the key number (e.g. 15 for F5)
            key_num = groups[0]
            if key_num in tilde_map:
                code = tilde_map[key_num]
            # Remove key num from groups to process mods correctly below
            # Actually, standard format is CSI key ; mods ~
            # But Kitty enhanced is CSI key ; mods:type ~
            pass

        if code == 0:
             # Unknown sequence
             return InputEvent(raw, "LEGACY", {}, False, f"Unknown ({decoded})")

        all_codes = [code]

        # Parse Mods/Type
        # For letters: CSI 1 ; mods:type A
        # For tilde:   CSI key ; mods:type ~
        mod_group_idx = 1 # Default for letters
        if terminator == '~': mod_group_idx = 1 # strict CSI key;mods~ format usually

        try:
            if len(groups) > mod_group_idx and groups[mod_group_idx]:
                mod_subs = groups[mod_group_idx].split(':')
                modifiers = int(mod_subs[0] or 1)
                if len(mod_subs) > 1:
                    event_type = int(mod_subs[1])
        except:
            pass

    # === HUMANIZE ===
    primary_code = all_codes[0]
    actual_mods = modifiers - 1
    mod_labels = []
    if actual_mods & 1: mod_labels.append("Shift")
    if actual_mods & 2: mod_labels.append("Alt")
    if actual_mods & 4: mod_labels.append("Ctrl")
    if actual_mods & 8: mod_labels.append("Super")

    key_name = f"Code:{primary_code}"
    # Standard ASCII
    if 32 <= primary_code <= 126: key_name = f"'{chr(primary_code)}'"

    # Common PUA / Control
    names = {
        13: "Enter", 9: "Tab", 27: "Escape", 127: "Backspace", 32: "Space",
        57373: "Up", 57374: "Down", 57375: "Right", 57376: "Left",
        57377: "Home", 57378: "End", 57379: "PageUp", 57380: "PageDown",
        57381: "F1", 57382: "F2", 57383: "F3", 57384: "F4"
    }
    if primary_code in names:
        key_name = names[primary_code]
    elif primary_code in KITTY_MOD_KEYS_RANGE:
        key_name = "ModKey"

    desc = key_name
    if mod_labels:
        desc += f" + {'+'.join(mod_labels)}"

    return InputEvent(raw, "KITTY", {
        'codes': all_codes, 'mods': modifiers, 'type': event_type
    }, is_release=(event_type==3), desc=desc)

def parse_win32(raw):
    # CSI Vk ; Sc ; Uc ; Kd ; Cs ; Rc _
    decoded = decode_utf8_safe(raw)

    if not decoded.endswith('_') or not decoded.startswith('ESC['):
        return InputEvent(raw, "RAW", {}, False, repr(decoded))

    content = decoded[4:-1]
    parts = content.split(';')

    try:
        parts += ['0'] * (6 - len(parts))
        vk = int(parts[0] or 0)
        uc = int(parts[2] or 0)
        kd = int(parts[3] or 0)
        cs = int(parts[4] or 0)

        mod_labels = []
        if cs & 0x0010: mod_labels.append("Shift")
        if cs & 0x0001: mod_labels.append("Right Alt")
        if cs & 0x0002: mod_labels.append("Left Alt")
        if cs & 0x0004: mod_labels.append("Right Ctrl")
        if cs & 0x0008: mod_labels.append("Left Ctrl")

        vk_map = {
            13: "Enter", 8: "Backspace", 9: "Tab", 27: "Escape", 32: "Space",
            37: "Left", 38: "Up", 39: "Right", 40: "Down",
            33: "PageUp", 34: "PageDown", 35: "End", 36: "Home",
            112: "F1", 113: "F2", 17: "Ctrl", 16: "Shift", 18: "Alt"
        }

        key_name = vk_map.get(vk, f"VK:{vk}")
        if uc > 32 and uc < 127:
            key_name = f"'{chr(uc)}'"

        desc = key_name
        filtered_mods = [m for m in mod_labels if key_name not in m]
        if filtered_mods:
            desc += f" + {'+'.join(filtered_mods)}"

        return InputEvent(raw, "WIN32", {
            'vk': vk, 'uc': uc, 'kd': kd, 'cs': cs
        }, is_release=(kd==0), desc=desc)

    except ValueError:
        return InputEvent(raw, "ERR", {}, False, "Parse Error")

# --- VERIFIERS ---

def v_match_kitty(target_code, target_mods=1):
    def f(e):
        if "ModKey" in e.desc: return False, None
        if e.protocol != "KITTY": return False, f"Wrong Protocol ({e.raw})"

        primary_code = e.params['codes'][0]
        if primary_code in KITTY_MOD_KEYS_RANGE: return False, None

        if target_code not in e.params['codes']:
            return False, f"Exp {target_code}, got {e.params['codes']}"

        if e.params['mods'] != target_mods:
            return False, f"Exp Mod {target_mods}, got {e.params['mods']}"

        return True, "OK"
    return f

def v_match_win32(vk, cs_mask=None, require_char=None):
    def f(e):
        if e.protocol == "WIN32" and e.params['vk'] in [16, 17, 18]: return False, None
        if e.protocol != "WIN32": return False, f"Wrong Protocol ({e.raw})"

        if e.params['vk'] != vk:
            return False, f"Exp VK {vk}, got {e.params['vk']}"

        if cs_mask is not None:
            if (e.params['cs'] & cs_mask) != cs_mask:
                return False, f"CS Mask Mismatch. Got {e.params['cs']}"

        if require_char is not None:
            if e.params['uc'] != require_char:
                return False, f"Exp Char {require_char}, got {e.params['uc']}"
        return True, "OK"
    return f

# --- TEST SUITES ---

class TestCase:
    def __init__(self, name, prompt, verifier):
        self.name = name
        self.prompt = prompt
        self.verifier = verifier

def create_tests(mode):
    tests = []
    def t(name, prompt, verifier):
        tests.append(TestCase(name, prompt, verifier))

    if mode == 'kitty':
        t("Letter 'a'", "Press 'a'",         v_match_kitty(97, 1))
        t("Shift + a",  "Press 'Shift + a'", v_match_kitty(97, 2))
        t("Ctrl + a",   "Press 'Ctrl + a'",  v_match_kitty(97, 5))

        t("Enter",      "Press 'Enter'",     v_match_kitty(13, 1))
        t("Backspace",  "Press 'Backspace'", v_match_kitty(127, 1))
        t("Tab",        "Press 'Tab'",       v_match_kitty(9, 1))
        t("Ctrl + i",   "Press 'Ctrl + i'",  v_match_kitty(105, 5))

        t("Left Arrow", "Press 'Left'", v_match_kitty(57376, 1))
        t("Home",       "Press 'Home'", v_match_kitty(57377, 1))

        t("F1",         "Press 'F1'",     v_match_kitty(57381, 1))
        t("Escape",     "Press 'Escape'", v_match_kitty(27, 1))

        t("Ctrl+Space", "Press 'Ctrl + Space'", v_match_kitty(32, 5))
    else:
        t("Letter 'a'", "Press 'a'",             v_match_win32(65, 0, 97))
        t("Shift + a",  "Press 'Shift + a'",     v_match_win32(65, 16, 65))
        t("Ctrl + a",   "Press 'Left Ctrl + a'", v_match_win32(65, 8, 1))

        t("Enter",      "Press 'Enter'",         v_match_win32(13, 0, 13))
        t("Backspace",  "Press 'Backspace'",     v_match_win32(8, 0, 8))
        t("Tab",        "Press 'Tab'",           v_match_win32(9, 0, 9))
        t("Ctrl + i",   "Press 'Left Ctrl + i'", v_match_win32(73, 8, 9))

        t("Left Arrow", "Press 'Left'", v_match_win32(37))
        t("Home",       "Press 'Home'", v_match_win32(36))

        t("F1",         "Press 'F1'",              v_match_win32(112))
        t("RAlt + F1",  "Press 'Right Alt + F1'",  v_match_win32(112, 1, 0))
        t("Alt + F1",   "Press 'Left ALt + F1'",   v_match_win32(112, 2, 0))
        t("RCtrl + F1", "Press 'Right Ctrl + F1'", v_match_win32(112, 4, 0))
        t("Ctrl + F1",  "Press 'Left Ctrl + F1'",  v_match_win32(112, 8, 0))

        t("Escape",     "Press 'Escape'", v_match_win32(27))

        # t("Shift",   "Press any 'Shift'",  v_match_win32(16, 16, 0))
        # t("RCtrl",   "Press 'Right Ctrl'", v_match_win32(17, 260, 0))
        # t("Ctrl",    "Press 'Left Ctrl'",  v_match_win32(17, 8, 0))
        # t("RAlt",    "Press 'Right Alt'",  v_match_win32(18, 257, 0))
        # t("Alt",     "Press 'Left Alt'",   v_match_win32(18, 2, 0))

        t("Ctrl+Space", "Press 'Left Ctrl + Space'", v_match_win32(32, 8, 32))

    return tests

# --- ENGINE ---

def run_session(mode):
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    tty.setraw(fd)

    if mode == 'kitty': write_screen(KITTY_ENABLE)
    elif mode == 'win32': write_screen(WIN32_ENABLE)

    def cleanup():
        if mode == 'kitty': write_screen(KITTY_DISABLE)
        elif mode == 'win32': write_screen(WIN32_DISABLE)
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        write_screen(b'\x1b[?25h')
        log_to_file("Session Ended.")
        print(f"\n{Colors.BOLD}Log saved to {LOG_FILE}{Colors.ENDC}")

    atexit.register(cleanup)
    write_screen(b'\x1b[?25l')

    tests = create_tests(mode)
    log_queue = deque(maxlen=20)

    start_time = time.time()
    skipped_cnt = 0
    passed_cnt = 0

    with open(LOG_FILE, "w") as f: f.write(f"--- START: {mode.upper()} ---\n")

    for idx, test in enumerate(tests):
        passed = False
        skipped = False
        log_to_file(f"--- TEST CASE: {test.name} ---") # ADDED: Log Current Test

        while not passed and not skipped:
            # 1. UI
            h = get_terminal_height()
            if h > 10 and log_queue.maxlen != h - 10:
                log_queue = deque(log_queue, maxlen=h - 10)

            write_screen(b'\x1b[2J\x1b[H')

            write_screen(f"{Colors.BLUE}{Colors.BOLD} PROTOCOL TESTER: {mode.upper()} {Colors.ENDC}\r\n")
            write_screen(f"{Colors.GRAY}" + "-"*60 + f"{Colors.ENDC}\r\n")

            elapsed = int(time.time() - start_time)
            write_screen(f" Case: {idx+1}/{len(tests)} | Passed: {passed_cnt} | Skipped: {skipped_cnt} | T: {elapsed}s\r\n")
            write_screen(f" {Colors.YELLOW}TEST: {test.name:<20}{Colors.ENDC} {Colors.BOLD}DO: {test.prompt}{Colors.ENDC}\r\n")
            write_screen(f" {Colors.RED}Ctrl+C{Colors.ENDC} Quit | {Colors.BLUE}Ctrl+D{Colors.ENDC} Skip\r\n")
            write_screen(f"{Colors.GRAY}" + "="*60 + f"{Colors.ENDC}\r\n")

            for line in log_queue: write_screen(line + b'\r\n')

            # 2. Input
            try:
                r, _, _ = select.select([fd], [], [], None)
                if not r: continue
                ch = os.read(fd, 1)
            except OSError: break
            if not ch: break

            raw_buf = ch
            if ch == b'\x1b':
                while True:
                    r, _, _ = select.select([fd], [], [], 0.005)
                    if not r: break
                    chunk = os.read(fd, 1024)
                    if not chunk: break
                    raw_buf += chunk
                    # Stop conditions:
                    # Kitty/Win32 ends in u or _
                    # Functional keys end in letter (64-126) or tilde (126)
                    # Simple check: if last byte is not digit/semicolon/bracket
                    last = raw_buf[-1]
                    if (0x40 <= last <= 0x7E) or last == 0x5F: break

            # 3. Parse
            event = parse_kitty(raw_buf) if mode == 'kitty' else parse_win32(raw_buf)
            log_to_file(f"IN: {repr(raw_buf)} -> {event.desc} {event.params}")

            # 4. Global Checks
            if (event.raw == b'\x03') or \
               (mode == 'kitty' and 99 in event.params.get('codes',[]) and event.params.get('mods')==5) or \
               (mode == 'win32' and event.params.get('vk')==67 and (event.params.get('cs',0)&12)):
                cleanup()
                sys.exit(0)

            if (event.raw == b'\x04') or \
               (mode == 'kitty' and 100 in event.params.get('codes',[]) and event.params.get('mods')==5) or \
               (mode == 'win32' and event.params.get('vk')==68 and (event.params.get('cs',0)&12)):
                skipped = True
                skipped_cnt += 1
                log_queue.append(f"{Colors.YELLOW}>>> SKIPPED{Colors.ENDC}".encode())
                break

            # 5. Verify
            style = Colors.GRAY if event.is_release else Colors.BOLD
            log_line = f"{style}[{'UP ' if event.is_release else 'DWN'}] {event.desc:<25} {Colors.GRAY}{event.params}{Colors.ENDC}"
            log_queue.append(log_line.encode())

            if not event.is_release:
                ok, msg = test.verifier(event)
                if ok:
                    passed = True
                    passed_cnt += 1
                    log_queue.append(f"{Colors.GREEN}>>> PASS{Colors.ENDC}".encode())
                    time.sleep(0.05)
                elif msg:
                    log_queue.append(f"{Colors.RED}FAIL: {msg}{Colors.ENDC}".encode())

    write_screen(b'\x1b[2J\x1b[H')
    print("Done.")

if __name__ == "__main__":
    print("1. Kitty\n2. Win32")
    c = input("Mode: ")
    if c == '1': run_session('kitty')
    elif c == '2': run_session('win32')