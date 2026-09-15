from flask import Flask, request, jsonify
import hmac, hashlib, requests, string, random
import json, codecs, time, urllib3, base64, logging, traceback
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

try:
    from protobuf_decoder.protobuf_decoder import Parser as ProtoParser
    PROTO_OK = True
except Exception as e:
    PROTO_OK = False; _proto_err = str(e)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(asctime)s | %(message)s")
log = logging.getLogger("ff")
app = Flask(__name__)

# ── KEYS ──────────────────────────────────────────────────────────────────── #
hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key     = bytes.fromhex(hex_key)
key_str = key.decode("latin-1")

REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"bn","PK":"ur","TW":"zh","EU":"en","RU":"ru","NA":"en","SAC":"es","BR":"pt"}
REGION_URLS = {
    "IND":"https://client.ind.freefiremobile.com/","ID":"https://clientbp.ggblueshark.com/",
    "BR":"https://client.us.freefiremobile.com/","ME":"https://clientbp.common.ggbluefox.com/",
    "VN":"https://clientbp.ggblueshark.com/","TH":"https://clientbp.common.ggbluefox.com/",
    "RU":"https://clientbp.ggblueshark.com/","BD":"https://clientbp.ggblueshark.com/",
    "PK":"https://clientbp.ggblueshark.com/","SG":"https://clientbp.ggblueshark.com/",
    "NA":"https://client.us.freefiremobile.com/","SAC":"https://client.us.freefiremobile.com/",
    "EU":"https://clientbp.ggblueshark.com/","TW":"https://clientbp.ggblueshark.com/"
}

_session = None
def get_session():
    global _session
    if _session is None:
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        _session = requests.Session()
        ret = Retry(total=1, backoff_factor=0.3, status_forcelist=[500,502,503,504])
        adp = HTTPAdapter(max_retries=ret)
        _session.mount("http://", adp); _session.mount("https://", adp)
    return _session

# ── PROTO ──────────────────────────────────────────────────────────────────── #
def enc_vr(N):
    H=[]
    while True:
        b=N&0x7F; N>>=7
        if N: b|=0x80
        H.append(b)
        if not N: break
    return bytes(H)

def make_proto(fields):
    pkt=bytearray()
    for f,v in fields.items():
        if isinstance(v,dict):
            nested=make_proto(v); pkt.extend(enc_vr((f<<3)|2)+enc_vr(len(nested))+nested)
        elif isinstance(v,int): pkt.extend(enc_vr((f<<3)|0)+enc_vr(v))
        elif isinstance(v,(str,bytes)):
            e=v.encode() if isinstance(v,str) else v
            pkt.extend(enc_vr((f<<3)|2)+enc_vr(len(e))+e)
    return pkt

def proto_parse(hex_str):
    if not PROTO_OK: return None
    try:
        def _p(rs):
            d={}
            for r in rs:
                fd={"wire_type":r.wire_type}
                if r.wire_type in ("varint","string","bytes"): fd["data"]=r.data
                elif r.wire_type=="length_delimited": fd["data"]=_p(r.data.results)
                d[r.field]=fd
            return d
        return json.loads(json.dumps(_p(ProtoParser().parse(hex_str))))
    except: return None

# ── AES ────────────────────────────────────────────────────────────────────── #
_K=bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
_I=bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
def aes_enc(h): c=AES.new(_K,AES.MODE_CBC,_I); return c.encrypt(pad(bytes.fromhex(h),AES.block_size)).hex()

# ── UTILS ──────────────────────────────────────────────────────────────────── #
def rand_name(p): return p+''.join(random.choices(string.ascii_uppercase+string.digits,k=6))
def rand_pass(): return "DANGER-"+''.join(random.choices(string.ascii_uppercase+string.digits,k=9))+"-CORE"
def encode_open_id(s):
    ks=[0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
        0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    return ''.join(chr(ord(c)^ks[i%len(ks)]) for i,c in enumerate(s))
def to_uni(s): return ''.join(c if 32<=ord(c)<=126 else f'\\u{ord(c):04x}' for c in s)
def extract_jwt(rb):
    try:
        txt=rb.decode("utf-8","ignore")
        i=txt.find("eyJhbGci")
        if i!=-1:
            raw=txt[i:].split("\x00")[0].split(" ")[0].strip()
            d2=raw.find(".",raw.find(".")+1)
            return raw[:d2+44] if d2!=-1 else raw[:500]
    except: pass
    try:
        d=proto_parse(rb.hex())
        t=(d or {}).get("8",{}).get("data","")
        if t and str(t).startswith("eyJ"): return str(t)
    except: pass
    return None

# ── REGISTER VARIANTS ─────────────────────────────────────────────────────── #
# Garena has multiple app_ids and source values — try them all
REGISTER_VARIANTS = [
    # (app_id, client_type, source, ua_suffix)
    ("100067", "2", "2", "ASUS_Z01QD ;Android 12;en;US;"),
    ("100067", "2", "1", "ASUS_Z01QD ;Android 12;en;US;"),
    ("100067", "2", "4", "ASUS_Z01QD ;Android 12;en;US;"),
    ("100067", "2", "2", "ASUS_I005DA ;Android 9;en;US;"),
    ("100067", "3", "2", "ASUS_Z01QD ;Android 12;en;US;"),
]

def try_register(pwd, ses):
    """Try register with multiple variants, return (uid, variant_info) or (None, errors)."""
    errors = []
    for app_id, ct, src, ua in REGISTER_VARIANTS:
        try:
            # Build body & sign
            data = f"password={pwd}&client_type={ct}&source={src}&app_id={app_id}"
            sig  = hmac.new(key, data.encode(), hashlib.sha256).hexdigest()
            r = ses.post(
                f"https://{app_id}.connect.garena.com/oauth/guest/register",
                headers={
                    "User-Agent": f"GarenaMSDK/4.0.19P8({ua})",
                    "Authorization": f"Signature {sig}",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip",
                    "Connection": "Keep-Alive"
                },
                data=data, timeout=15
            )
            try: rj = r.json()
            except: rj = {"raw": r.text[:200]}
            entry = {"app_id":app_id,"client_type":ct,"source":src,"status":r.status_code,"body":rj}
            uid = rj.get("uid")
            if uid:
                entry["SUCCESS"] = True
                return uid, entry, None
            errors.append(entry)
        except Exception as e:
            errors.append({"app_id":app_id,"client_type":ct,"source":src,"exception":str(e)})
    return None, None, errors

TOKEN_SECRETS = [key_str, hex_key, "100067"]

def try_token(uid, pwd, ses):
    """Try token grant with multiple client_secret variants."""
    errors = []
    for cs_label, cs in [("latin1",key_str),("hex_key",hex_key),("app_id","100067")]:
        try:
            r = ses.post(
                "https://100067.connect.garena.com/oauth/guest/token/grant",
                headers={
                    "Accept-Encoding":"gzip","Connection":"Keep-Alive",
                    "Content-Type":"application/x-www-form-urlencoded",
                    "Host":"100067.connect.garena.com",
                    "User-Agent":"GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)"
                },
                data={"uid":uid,"password":pwd,"response_type":"token",
                      "client_type":"2","client_secret":cs,"client_id":"100067"},
                timeout=15
            )
            try: rj=r.json()
            except: rj={"raw":r.text[:200]}
            entry={"secret":cs_label,"status":r.status_code,"body":rj}
            if rj.get("open_id") and rj.get("access_token"):
                entry["SUCCESS"]=True
                return rj["open_id"], rj["access_token"], entry, None
            errors.append(entry)
        except Exception as e:
            errors.append({"secret":cs_label,"exception":str(e)})
    return None, None, None, errors

BASE_PL=(
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
def build_login_pl(at,oi,lang):
    d=BASE_PL.replace(b"{LANG}",lang.encode())
    d=d.replace(b"afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390",at.encode())
    d=d.replace(b"1d8ec0240ede109973f3321b9354b44d",oi.encode())
    return d
def login_url(r): return "https://loginbp.common.ggbluefox.com/MajorLogin" if r.lower()=="me" else "https://loginbp.ggblueshark.com/MajorLogin"
def login_hdrs(): return {"Accept-Encoding":"gzip","Authorization":"Bearer","Connection":"Keep-Alive","Content-Type":"application/x-www-form-urlencoded","Expect":"100-continue","Host":"loginbp.ggblueshark.com","ReleaseVersion":"OB52","User-Agent":"Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)","X-GA":"v1 1","X-Unity-Version":"2018.4.11f1"}

# ════════════════════════════════════════
#  MAIN FLOW
# ════════════════════════════════════════
def create_acc(region, name_prefix):
    T={}; ses=get_session(); pwd=rand_pass()

    # S1
    uid, reg_ok, reg_errors = try_register(pwd, ses)
    T["s1_register"] = reg_ok if reg_ok else {"all_variants_failed": reg_errors}
    if not uid: T["fail"]="s1_register: all variants returned no uid"; return None,T

    # S2
    open_id, access_token, tok_ok, tok_errors = try_token(uid, pwd, ses)
    T["s2_token"] = tok_ok if tok_ok else {"all_secrets_failed": tok_errors}
    if not open_id: T["fail"]="s2_token: all secrets returned no open_id"; return None,T

    # S3
    try:
        enc_oi  = encode_open_id(open_id)
        field   = codecs.decode(to_uni(enc_oi),"unicode_escape").encode("latin-1")
        name    = rand_name(name_prefix)
        pf      = {1:name,2:access_token,3:open_id,5:102000007,6:4,7:1,13:1,14:field,15:"en",16:1,17:1}
        body    = bytes.fromhex(aes_enc(make_proto(pf).hex()))
        r3=ses.post("https://loginbp.ggblueshark.com/MajorRegister",headers={"Accept-Encoding":"gzip","Authorization":"Bearer","Connection":"Keep-Alive","Content-Type":"application/x-www-form-urlencoded","Expect":"100-continue","Host":"loginbp.ggblueshark.com","ReleaseVersion":"OB52","User-Agent":"Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)","X-GA":"v1 1","X-Unity-Version":"2018.4.11f1"},data=body,verify=False,timeout=20)
        T["s3_major_reg"]={"status":r3.status_code,"len":len(r3.content),"hex":r3.content.hex()[:100]}
    except Exception as e:
        T["s3_major_reg"]={"exception":str(e),"tb":traceback.format_exc()[-300:]}
        T["fail"]="s3_major_reg"; return None,T

    # S4
    lang=REGION_LANG.get(region,"en"); jwt=None
    try:
        raw=build_login_pl(access_token,open_id,lang)
        enc=bytes.fromhex(aes_enc(raw.hex()))
        r4=ses.post(login_url(region),headers=login_hdrs(),data=enc,verify=False,timeout=20)
        T["s4_login"]={"status":r4.status_code,"len":len(r4.content),"hex":r4.content.hex()[:120]}
        if r4.status_code==200 and len(r4.content)>=10:
            jwt=extract_jwt(r4.content)
            T["s4_login"]["jwt_found"]=bool(jwt); T["s4_login"]["jwt_prefix"]=jwt[:40] if jwt else None
    except Exception as e:
        T["s4_login"]={"exception":str(e),"tb":traceback.format_exc()[-300:]}
        T["fail"]="s4_login"; return None,T

    if lang not in ("ar","en") and jwt:
        try:
            rk="RU" if region=="RU" else region
            cr=bytes.fromhex(aes_enc(make_proto({1:rk}).hex()))
            rc=ses.post("https://loginbp.ggblueshark.com/ChooseRegion",headers={"User-Agent":"Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)","Connection":"Keep-Alive","Accept-Encoding":"gzip","Content-Type":"application/x-www-form-urlencoded","Expect":"100-continue","Authorization":f"Bearer {jwt}","X-Unity-Version":"2018.4.11f1","X-GA":"v1 1","ReleaseVersion":"OB52"},data=cr,verify=False,timeout=15)
            T["s4b_choose_region"]={"status":rc.status_code,"hex":rc.content.hex()[:80]}
            if rc.status_code==200:
                raw2=build_login_pl(access_token,open_id,lang); enc2=bytes.fromhex(aes_enc(raw2.hex()))
                r4b=ses.post(login_url(region),headers=login_hdrs(),data=enc2,verify=False,timeout=20)
                T["s4c_login2"]={"status":r4b.status_code,"len":len(r4b.content),"hex":r4b.content.hex()[:120]}
                jwt=extract_jwt(r4b.content); T["s4c_login2"]["jwt_found"]=bool(jwt)
        except Exception as e:
            T["s4b_choose_region"]={"exception":str(e)}

    if not jwt: T["fail"]="s4_login: no JWT"; return None,T

    # S5
    try:
        parts=jwt.split(".")
        b64=parts[1]+"="*((4-len(parts[1])%4)%4)
        dec=json.loads(base64.urlsafe_b64decode(b64).decode())
        ext_id=dec.get("external_id",""); sig_md5=dec.get("signature_md5","")
        now=str(datetime.now())[:19]
        PL=(b':\x071.111.2\xaa\x01\x02ar\xb2\x01 55ed759fcf94f85813e57b2ec8492f5c\xba\x01\x014\xea\x01@6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae\x9a\x06\x014\xa2\x06\x014')
        PL=PL.replace(b"2023-12-24 04:21:34",now.encode())
        PL=PL.replace(b"15f5ba1de5234a2e73cc65b6f34ce4b299db1af616dd1dd8a6f31b147230e5b6",access_token.encode())
        PL=PL.replace(b"4666ecda0003f1809655a7a8698573d0",ext_id.encode())
        PL=PL.replace(b"7428b253defc164018c604a1ebbfebdf",sig_md5.encode())
        enc5=bytes.fromhex(aes_enc(PL.hex()))
        link=REGION_URLS.get(region,"https://clientbp.ggblueshark.com/")
        r5=ses.post(f"{link}GetLoginData",headers={"Expect":"100-continue","Authorization":f"Bearer {jwt}","X-Unity-Version":"2018.4.11f1","X-GA":"v1 1","ReleaseVersion":"OB52","Content-Type":"application/x-www-form-urlencoded","User-Agent":"Dalvik/2.1.0 (Linux; U; Android 10; G011A Build/PI)","Connection":"close","Accept-Encoding":"gzip, deflate, br"},data=enc5,verify=False,timeout=20)
        gld=proto_parse(r5.content.hex())
        T["s5_getlogindata"]={"status":r5.status_code,"len":len(r5.content),"keys":list(gld.keys()) if gld else None}
    except Exception as e:
        T["s5_getlogindata"]={"exception":str(e)}

    return {"uid":uid,"password":pwd,"name":name,"region":region,"status":"full_login","stage":"complete"},T

# ── ROUTES ─────────────────────────────────────────────────────────────────── #
@app.route("/gen", methods=["GET"])
def generate_accounts():
    name=request.args.get("name","HUSTLER"); region=request.args.get("region","IND").upper()
    try: count=max(1,min(10,int(request.args.get("count","1"))))
    except: count=1
    if region not in REGION_LANG: region="IND"
    results=[]; failures=[]
    for i in range(count*5):
        if len(results)>=count: break
        result,trace=create_acc(region,name)
        if result: results.append(result)
        else: failures.append({"attempt":i+1,"failed_at":trace.get("fail"),"trace":trace})
        if len(results)<count: time.sleep(1)
    return jsonify({"success":True,"total_requested":count,"total_created":len(results),"accounts":results,"debug_failures":failures[:2] if not results else []})

@app.route("/trace", methods=["GET"])
def trace_single():
    region=request.args.get("region","IND").upper(); name=request.args.get("name","TEST")
    if region not in REGION_LANG: region="IND"
    result,trace=create_acc(region,name)
    return jsonify({"result":result,"trace":trace,"failed_at":trace.get("fail") if not result else "SUCCESS"})

@app.route("/probe-register", methods=["GET"])
def probe_register():
    """
    Brute-probe Garena register with every known variant combination.
    Shows exact response for each. Use to find which params Garena still accepts.
    """
    ses=get_session(); pwd=rand_pass(); results=[]
    combos=[
        ("100067","2","2","GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)"),
        ("100067","2","1","GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)"),
        ("100067","2","4","GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)"),
        ("100067","2","3","GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)"),
        ("100067","3","2","GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)"),
        ("100067","1","2","GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)"),
        ("100067","2","2","GarenaMSDK/3.2.10P5(ASUS_Z01QD ;Android 10;en;US;)"),
        ("100067","2","2","GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 9;en;US;)"),
    ]
    for app_id,ct,src,ua in combos:
        try:
            data=f"password={pwd}&client_type={ct}&source={src}&app_id={app_id}"
            sig=hmac.new(key,data.encode(),hashlib.sha256).hexdigest()
            r=ses.post(
                f"https://{app_id}.connect.garena.com/oauth/guest/register",
                headers={"User-Agent":ua,"Authorization":f"Signature {sig}","Content-Type":"application/x-www-form-urlencoded","Accept-Encoding":"gzip","Connection":"Keep-Alive"},
                data=data,timeout=12
            )
            try: body=r.json()
            except: body={"raw":r.text[:300]}
            entry={"app_id":app_id,"ct":ct,"src":src,"ua_short":ua[12:40],"status":r.status_code,"body":body,"has_uid":bool(body.get("uid"))}
            results.append(entry)
            if body.get("uid"): break  # found working combo
        except Exception as e:
            results.append({"app_id":app_id,"ct":ct,"src":src,"exception":str(e)})
    working=[r for r in results if r.get("has_uid")]
    return jsonify({"working_combos":working,"all_results":results,"password_used":pwd})

@app.route("/imports")
def check_imports():
    s={}
    for mod,imp in [("hmac","import hmac"),("pycryptodome","from Crypto.Cipher import AES"),("protobuf_decoder","from protobuf_decoder.protobuf_decoder import Parser"),("requests","import requests")]:
        try: exec(imp); s[mod]="ok"
        except Exception as e: s[mod]=str(e)
    s["proto_ok_startup"]=PROTO_OK
    return jsonify(s)

@app.route("/ping-garena")
def ping():
    try: r=requests.get("https://100067.connect.garena.com/",timeout=8); return jsonify({"reachable":True,"status":r.status_code})
    except Exception as e: return jsonify({"reachable":False,"error":str(e)})

@app.route("/")
def home():
    return jsonify({"endpoints":{"/probe-register":"FIRST — try all register variants","//trace":"?region=IND full flow trace","/gen":"?name=X&count=N&region=R","/imports":"package check","/ping-garena":"network check"},"regions":list(REGION_LANG.keys())})

@app.route("/health")
def health(): return jsonify({"status":"healthy"})

def application(environ,start_response): return app(environ,start_response)
if __name__=="__main__": app.run(host="0.0.0.0",port=3000,debug=True)
