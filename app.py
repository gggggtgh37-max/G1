from flask import Flask, request, jsonify
import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from protobuf_decoder.protobuf_decoder import Parser
import codecs
import time
from datetime import datetime
import urllib3
import base64
import concurrent.futures
import threading
import logging

logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(asctime)s | %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("ff-gen")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ── KEYS ──────────────────────────────────────────────────────────────────── #
hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key      = bytes.fromhex(hex_key)
key_str  = key.decode("latin-1")   # decoded string form for form fields

REGION_LANG = {
    "ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th",
    "BD":"bn","PK":"ur","TW":"zh","EU":"en","RU":"ru",
    "NA":"en","SAC":"es","BR":"pt"
}
REGION_URLS = {
    "IND":"https://client.ind.freefiremobile.com/",
    "ID":"https://clientbp.ggblueshark.com/",
    "BR":"https://client.us.freefiremobile.com/",
    "ME":"https://clientbp.common.ggbluefox.com/",
    "VN":"https://clientbp.ggblueshark.com/",
    "TH":"https://clientbp.common.ggbluefox.com/",
    "RU":"https://clientbp.ggblueshark.com/",
    "BD":"https://clientbp.ggblueshark.com/",
    "PK":"https://clientbp.ggblueshark.com/",
    "SG":"https://clientbp.ggblueshark.com/",
    "NA":"https://client.us.freefiremobile.com/",
    "SAC":"https://client.us.freefiremobile.com/",
    "EU":"https://clientbp.ggblueshark.com/",
    "TW":"https://clientbp.ggblueshark.com/"
}

# ── SESSION ────────────────────────────────────────────────────────────────── #
thread_local = threading.local()
def get_session():
    if not hasattr(thread_local, "session"):
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        s = requests.Session()
        r = Retry(total=2, backoff_factor=0.5, status_forcelist=[429,500,502,503,504])
        a = HTTPAdapter(max_retries=r, pool_connections=100, pool_maxsize=100)
        s.mount("http://", a); s.mount("https://", a)
        thread_local.session = s
    return thread_local.session

# ── PROTO ──────────────────────────────────────────────────────────────────── #
def enc_vr(N):
    H=[]
    while True:
        b=N&0x7F; N>>=7
        if N: b|=0x80
        H.append(b)
        if not N: break
    return bytes(H)

def proto_varint(f,v): return enc_vr((f<<3)|0)+enc_vr(v)
def proto_len(f,v):
    e=v.encode() if isinstance(v,str) else v
    return enc_vr((f<<3)|2)+enc_vr(len(e))+e

def make_proto(fields):
    pkt=bytearray()
    for f,v in fields.items():
        if isinstance(v,dict): pkt.extend(proto_len(f,make_proto(v)))
        elif isinstance(v,int): pkt.extend(proto_varint(f,v))
        elif isinstance(v,(str,bytes)): pkt.extend(proto_len(f,v))
    return pkt

# ── AES ────────────────────────────────────────────────────────────────────── #
_K = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
_I = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
def aes_enc(hex_str: str) -> str:
    raw = bytes.fromhex(hex_str)
    c   = AES.new(_K, AES.MODE_CBC, _I)
    return c.encrypt(pad(raw, AES.block_size)).hex()

# ── PROTO PARSER ───────────────────────────────────────────────────────────── #
def parse_proto_results(results):
    d={}
    for r in results:
        fd={"wire_type":r.wire_type}
        if r.wire_type in ("varint","string","bytes"): fd["data"]=r.data
        elif r.wire_type=="length_delimited": fd["data"]=parse_proto_results(r.data.results)
        d[r.field]=fd
    return d

def proto_to_dict(hex_str):
    try:
        parsed=Parser().parse(hex_str)
        return json.loads(json.dumps(parse_proto_results(parsed)))
    except Exception as e:
        return None

# ── HELPERS ────────────────────────────────────────────────────────────────── #
def rand_name(prefix): return prefix+''.join(random.choices(string.ascii_uppercase+string.digits,k=6))
def rand_pass(): return "DANGER-"+''.join(random.choices(string.ascii_uppercase+string.digits,k=9))+"-CORE"

def encode_open_id(original):
    ks=[0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,
        0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
        0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,
        0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    enc=""
    for i,c in enumerate(original): enc+=chr(ord(c)^ks[i%len(ks)])
    return enc

def to_unicode_esc(s): return ''.join(c if 32<=ord(c)<=126 else f'\\u{ord(c):04x}' for c in s)

def extract_jwt(resp_bytes: bytes):
    # strategy 1: text scan
    try:
        txt=resp_bytes.decode("utf-8","ignore")
        idx=txt.find("eyJhbGci")
        if idx!=-1:
            raw=txt[idx:].split("\x00")[0].split(" ")[0].strip()
            dot2=raw.find(".",raw.find(".")+1)
            return raw[:dot2+44] if dot2!=-1 else raw[:500]
    except: pass
    # strategy 2: protobuf field 8
    try:
        d=proto_to_dict(resp_bytes.hex())
        t=d.get("8",{}).get("data","") if d else ""
        if t and t.startswith("eyJ"): return t
    except: pass
    return None

BASE_LOGIN_PL = (
    b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13'
    b'B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)'
    b'J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300'
    b'z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f'
    b'\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2'
    b'\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f'
    b'\xa2\x01\x0e105.235.139.91\xaa\x01\x02{LANG}'
    b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld'
    b'\xca\x01\x10Asus ASUS_I005DA'
    b'\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390'
    b'\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI'
    b'\xca\x03 7428b253defc164018c604a1ebbfebdf'
    b'\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07'
    b'\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02'
    b'\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm'
    b'\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9'
    b'|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk'
    b'\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692'
    b'\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android'
    b'\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+'
    b'fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2'
    b'\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014'
    b'\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
)

def build_login_payload(access_token, open_id, lang):
    d = BASE_LOGIN_PL.replace(b"{LANG}", lang.encode("ascii"))
    d = d.replace(b"afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390", access_token.encode())
    d = d.replace(b"1d8ec0240ede109973f3321b9354b44d", open_id.encode())
    return d

def login_url(region): return "https://loginbp.common.ggbluefox.com/MajorLogin" if region.lower()=="me" else "https://loginbp.ggblueshark.com/MajorLogin"
def login_hdrs(): return {
    "Accept-Encoding":"gzip","Authorization":"Bearer","Connection":"Keep-Alive",
    "Content-Type":"application/x-www-form-urlencoded","Expect":"100-continue",
    "Host":"loginbp.ggblueshark.com","ReleaseVersion":"OB52",
    "User-Agent":"Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
    "X-GA":"v1 1","X-Unity-Version":"2018.4.11f1"
}

# ═══════════════════════════════════════════════════
# FULL TRACE FLOW — returns (result_or_None, trace_dict)
# ═══════════════════════════════════════════════════
def create_acc_traced(region, name_prefix):
    trace = {}
    password = rand_pass()
    session  = get_session()

    # ── STEP 1: GUEST REGISTER ──────────────────── #
    data = f"password={password}&client_type=2&source=2&app_id=100067"
    sig  = hmac.new(key, data.encode(), hashlib.sha256).hexdigest()
    try:
        r = session.post(
            "https://100067.connect.garena.com/oauth/guest/register",
            headers={
                "User-Agent":"GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
                "Authorization":f"Signature {sig}",
                "Content-Type":"application/x-www-form-urlencoded",
                "Accept-Encoding":"gzip","Connection":"Keep-Alive"
            },
            data=data, timeout=30
        )
        rj = r.json()
        trace["step1_register"] = {"status": r.status_code, "body": rj}
        uid = rj.get("uid")
        if not uid:
            trace["failed_at"] = "step1_register — no uid"
            return None, trace
    except Exception as e:
        trace["step1_register"] = {"exception": str(e)}
        trace["failed_at"] = "step1_register — exception"
        return None, trace

    # ── STEP 2: TOKEN GRANT ─────────────────────── #
    # Try both key formats — latin-1 first, then raw hex string as fallback
    open_id = access_token = None
    for secret_attempt, cs in enumerate([key_str, hex_key, "100067"]):
        try:
            r2 = session.post(
                "https://100067.connect.garena.com/oauth/guest/token/grant",
                headers={
                    "Accept-Encoding":"gzip","Connection":"Keep-Alive",
                    "Content-Type":"application/x-www-form-urlencoded",
                    "Host":"100067.connect.garena.com",
                    "User-Agent":"GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)"
                },
                data={"uid":uid,"password":password,"response_type":"token",
                      "client_type":"2","client_secret":cs,"client_id":"100067"},
                timeout=30
            )
            rj2 = r2.json()
            trace[f"step2_token_secret_{secret_attempt}"] = {
                "status": r2.status_code,
                "body":   rj2,
                "client_secret_used": cs[:20]+"..." if len(cs)>20 else cs
            }
            if rj2.get("open_id") and rj2.get("access_token"):
                open_id      = rj2["open_id"]
                access_token = rj2["access_token"]
                trace["step2_token_success_with_secret"] = secret_attempt
                break
        except Exception as e:
            trace[f"step2_token_secret_{secret_attempt}_err"] = str(e)

    if not open_id or not access_token:
        trace["failed_at"] = "step2_token — all client_secret attempts failed"
        return None, trace

    # ── STEP 3: MAJOR REGISTER ──────────────────── #
    try:
        enc_result = encode_open_id(open_id)
        field_esc  = to_unicode_esc(enc_result)
        field      = codecs.decode(field_esc, "unicode_escape").encode("latin-1")
        name       = rand_name(name_prefix)

        payload_fields = {1:name,2:access_token,3:open_id,5:102000007,6:4,7:1,13:1,14:field,15:"en",16:1,17:1}
        body = bytes.fromhex(aes_enc(make_proto(payload_fields).hex()))
        r3   = session.post(
            "https://loginbp.ggblueshark.com/MajorRegister",
            headers={
                "Accept-Encoding":"gzip","Authorization":"Bearer","Connection":"Keep-Alive",
                "Content-Type":"application/x-www-form-urlencoded","Expect":"100-continue",
                "Host":"loginbp.ggblueshark.com","ReleaseVersion":"OB52",
                "User-Agent":"Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA":"v1 1","X-Unity-Version":"2018.4.11f1"
            },
            data=body, verify=False, timeout=30
        )
        trace["step3_major_register"] = {
            "status": r3.status_code,
            "resp_len": len(r3.content),
            "resp_hex_prefix": r3.content.hex()[:80]
        }
    except Exception as e:
        trace["step3_major_register"] = {"exception": str(e)}
        trace["failed_at"] = "step3_major_register — exception"
        return None, trace

    # ── STEP 4: LOGIN ───────────────────────────── #
    lang = REGION_LANG.get(region, "en")
    try:
        raw_pl = build_login_payload(access_token, open_id, lang)
        enc_pl = bytes.fromhex(aes_enc(raw_pl.hex()))
        r4     = session.post(login_url(region), headers=login_hdrs(), data=enc_pl, verify=False, timeout=30)
        trace["step4_login"] = {
            "status": r4.status_code,
            "resp_len": len(r4.content),
            "resp_hex_prefix": r4.content.hex()[:120]
        }
        jwt = None
        if r4.status_code == 200 and len(r4.content) >= 10:
            jwt = extract_jwt(r4.content)
            trace["step4_login"]["jwt_found"] = bool(jwt)
            trace["step4_login"]["jwt_prefix"] = jwt[:30] if jwt else None
    except Exception as e:
        trace["step4_login"] = {"exception": str(e)}
        trace["failed_at"] = "step4_login — exception"
        return None, trace

    # Non-ar/en → ChooseRegion path
    if lang not in ("ar","en") and jwt:
        try:
            region_key = "RU" if region=="RU" else region
            cr_body    = bytes.fromhex(aes_enc(make_proto({1:region_key}).hex()))
            r_cr = session.post(
                "https://loginbp.ggblueshark.com/ChooseRegion",
                headers={
                    "User-Agent":"Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)",
                    "Connection":"Keep-Alive","Accept-Encoding":"gzip",
                    "Content-Type":"application/x-www-form-urlencoded","Expect":"100-continue",
                    "Authorization":f"Bearer {jwt}","X-Unity-Version":"2018.4.11f1",
                    "X-GA":"v1 1","ReleaseVersion":"OB52"
                },
                data=cr_body, verify=False, timeout=30
            )
            trace["step4b_choose_region"] = {"status": r_cr.status_code, "resp_hex": r_cr.content.hex()[:80]}
            if r_cr.status_code == 200:
                # second login
                raw_pl2 = build_login_payload(access_token, open_id, lang)
                enc_pl2 = bytes.fromhex(aes_enc(raw_pl2.hex()))
                r4b     = session.post(login_url(region), headers=login_hdrs(), data=enc_pl2, verify=False, timeout=30)
                trace["step4c_login2"] = {"status": r4b.status_code, "resp_len": len(r4b.content), "resp_hex_prefix": r4b.content.hex()[:120]}
                jwt = extract_jwt(r4b.content)
                trace["step4c_login2"]["jwt_found"] = bool(jwt)
        except Exception as e:
            trace["step4b_choose_region"] = {"exception": str(e)}

    if not jwt:
        trace["failed_at"] = "step4_login — no JWT extracted from response"
        return None, trace

    # ── STEP 5: GET PAYLOAD / LOGIN DATA ────────── #
    try:
        parts = jwt.split(".")
        b64   = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        dec   = json.loads(base64.urlsafe_b64decode(b64).decode("utf-8"))
        ext_id  = dec.get("external_id","")
        sig_md5 = dec.get("signature_md5","")
        now     = str(datetime.now())[:19]

        PL = (b':\x071.111.2\xaa\x01\x02ar\xb2\x01 55ed759fcf94f85813e57b2ec8492f5c'
              b'\xba\x01\x014\xea\x01@6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae'
              b'\x9a\x06\x014\xa2\x06\x014')
        PL = PL.replace(b"2023-12-24 04:21:34", now.encode())
        PL = PL.replace(b"15f5ba1de5234a2e73cc65b6f34ce4b299db1af616dd1dd8a6f31b147230e5b6", access_token.encode())
        PL = PL.replace(b"4666ecda0003f1809655a7a8698573d0", ext_id.encode())
        PL = PL.replace(b"7428b253defc164018c604a1ebbfebdf", sig_md5.encode())

        enc_pl5 = bytes.fromhex(aes_enc(PL.hex()))
        link    = REGION_URLS.get(region, "https://clientbp.ggblueshark.com/")
        r5      = session.post(
            f"{link}GetLoginData",
            headers={
                "Expect":"100-continue","Authorization":f"Bearer {jwt}",
                "X-Unity-Version":"2018.4.11f1","X-GA":"v1 1","ReleaseVersion":"OB52",
                "Content-Type":"application/x-www-form-urlencoded",
                "User-Agent":"Dalvik/2.1.0 (Linux; U; Android 10; G011A Build/PI)",
                "Connection":"close","Accept-Encoding":"gzip, deflate, br"
            },
            data=enc_pl5, verify=False, timeout=20
        )
        gld = proto_to_dict(r5.content.hex())
        trace["step5_getlogindata"] = {
            "status": r5.status_code,
            "resp_len": len(r5.content),
            "parsed_keys": list(gld.keys()) if gld else None
        }
    except Exception as e:
        trace["step5_getlogindata"] = {"exception": str(e)}
        trace["failed_at"] = "step5_getlogindata — exception"
        return None, trace

    return {
        "uid": uid, "password": password,
        "name": name, "region": region,
        "status": "full_login", "stage": "complete"
    }, trace

# ── WRAPPER FOR THREAD POOL ────────────────────────────────────────────────── #
def create_single_account(args):
    name_prefix, region = args
    for attempt in range(3):
        try:
            result, trace = create_acc_traced(region, name_prefix)
            if result and result.get("status") == "full_login":
                return result, trace
            log.warning(f"attempt {attempt+1} failed at: {trace.get('failed_at','unknown')}")
            time.sleep(1)
        except Exception as e:
            log.error(f"attempt {attempt+1} outer exception: {e}")
            time.sleep(1)
    return None, {"failed_at":"all 3 retries exhausted"}

# ── ROUTES ─────────────────────────────────────────────────────────────────── #
@app.route("/gen", methods=["GET"])
def generate_accounts():
    name   = request.args.get("name","HUSTLER")
    region = request.args.get("region","IND").upper()
    try:    count = max(1, min(15, int(request.args.get("count","1"))))
    except: count = 1
    if region not in REGION_LANG: region = "IND"

    results      = []
    attempts     = 0
    failure_log  = []
    max_attempts = count * 10

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        while len(results) < count and attempts < max_attempts:
            batch   = min(count - len(results), 5)
            futures = [executor.submit(create_single_account, (name, region)) for _ in range(batch)]
            for future in concurrent.futures.as_completed(futures):
                attempts += 1
                result, trace = future.result()
                if result and result.get("status") == "full_login":
                    results.append(result)
                else:
                    failure_log.append({"attempt": attempts, "failed_at": trace.get("failed_at"), "trace": trace})
                if len(results) >= count: break
            if len(results) < count: time.sleep(2)

    return jsonify({
        "success":          True,
        "total_requested":  count,
        "total_created":    len(results),
        "accounts":         results,
        "attempts_made":    attempts,
        # when 0 created, show WHY — last failure trace
        "debug_last_failure": failure_log[-1] if failure_log and not results else None,
        "all_failures_summary": [f.get("failed_at") for f in failure_log] if not results else []
    })

@app.route("/trace", methods=["GET"])
def trace_one():
    """Single account attempt with FULL trace — use this to diagnose."""
    region = request.args.get("region","IND").upper()
    name   = request.args.get("name","TEST")
    if region not in REGION_LANG: region = "IND"
    result, trace = create_acc_traced(region, name)
    return jsonify({
        "result": result,
        "trace":  trace,
        "failed_at": trace.get("failed_at") if not result else "SUCCESS"
    })

@app.route("/")
def home():
    return jsonify({
        "endpoints": {
            "/gen":   "?name=NAME&count=N&region=REGION",
            "/trace": "?region=REGION — single attempt, full step trace (USE THIS TO DEBUG)",
            "/health":"liveness"
        },
        "regions": list(REGION_LANG.keys())
    })

@app.route("/health")
def health():
    return jsonify({"status":"healthy"})

def application(environ, start_response):
    return app(environ, start_response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)
