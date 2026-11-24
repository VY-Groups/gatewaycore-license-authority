#!/usr/bin/env python3
"""Real HTTPS operator MFA and role checks using disposable certificates and PostgreSQL."""
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

assert os.environ.get("CI") == "true" and os.environ.get("GITHUB_ACTIONS") == "true"
ROOT = Path.cwd()
PORTAL = ROOT / "tools/LicensePortal"
def check(ok, name):
    if not ok:
        raise AssertionError(name)
    print("PASS:", name, flush=True)

def cert(root, name, usage):
    crt, key = root / (name + ".crt"), root / (name + ".key")
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1",
                    "-subj",f"/CN={name}","-addext",f"extendedKeyUsage={usage}",
                    "-addext","subjectAltName=IP:127.0.0.1","-keyout",str(key),"-out",str(crt)],
                   check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return crt,key

def hash_password(password):
    salt = os.urandom(16)
    subkey = hashlib.pbkdf2_hmac("sha512",password.encode(),salt,100000,32)
    return base64.b64encode(b"\x01" + struct.pack(">III",2,100000,16) + salt + subkey).decode()

with tempfile.TemporaryDirectory(prefix="gc-portal-ci-") as td:
    root = Path(td)
    server, serverkey = cert(root,"portal","serverAuth")
    alice, alicekey = cert(root,"alice","clientAuth")
    bob,bobkey = cert(root,"bob","clientAuth")
    unknown,unknownkey = cert(root,"unknown","clientAuth")
    def pin(path):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest().upper()
    pins=root/"pins.json"; hashes=root/"hashes.json"
    pins.write_text(json.dumps({pin(alice):{"id":"alice","role":"requester"},pin(bob):{"id":"bob","role":"reviewer"}}))
    passwords={"alice":base64.b64encode(os.urandom(24)).decode(),"bob":base64.b64encode(os.urandom(24)).decode()}
    hashes.write_text(json.dumps({name:hash_password(value) for name,value in passwords.items()}))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0)); port=sock.getsockname()[1]
    origin=f"https://127.0.0.1:{port}"
    env=os.environ.copy()
    env.update({"ASPNETCORE_URLS":origin,"ASPNETCORE_ENVIRONMENT":"Production",
                "ASPNETCORE_Kestrel__Certificates__Default__Path":str(server),
                "ASPNETCORE_Kestrel__Certificates__Default__KeyPath":str(serverkey),
                "Portal__Origin":origin,"Portal__OperatorPins":str(pins),"Portal__PasswordHashes":str(hashes),
                "ConnectionStrings__Licensing":"Host=127.0.0.1;Database=gatewaycore_ci;Username=gc_portal_requester;Password=disposable-ci-runtime",
                "ConnectionStrings__LicensingReviewer":"Host=127.0.0.1;Database=gatewaycore_ci;Username=gc_portal_reviewer;Password=disposable-ci-runtime"})
    log=root/"portal.log"
    def client(crt=None,key=None):
        context=ssl.create_default_context(cafile=str(server))
        if crt: context.load_cert_chain(crt,key)
        return urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
    def request(c,path,data=None,cookie=None,expected=200,csrf=True):
        headers={}
        if data is not None:
            headers={"Content-Type":"application/json"}
            if csrf:headers.update({"Origin":origin,"X-GC-Portal":"1"})
        if cookie:headers["Cookie"]=cookie
        req=urllib.request.Request(origin+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
        try:
            with c.open(req,timeout=4) as res:
                status,body,response_headers=res.status,res.read(),res.headers
        except urllib.error.HTTPError as exc:
            status,body,response_headers=exc.code,exc.read(),exc.headers
        check(status==expected,f"{path}: {expected}, got {status}")
        return (json.loads(body) if body and response_headers.get("Content-Type","").startswith("application/json") else body),response_headers
    with log.open("w+") as out:
        process=subprocess.Popen(["dotnet",str(PORTAL/"bin/Release/net10.0/LicensePortal.dll")],cwd=PORTAL,env=env,stdout=out,stderr=subprocess.STDOUT)
        try:
            alice_client=client(alice,alicekey);bob_client=client(bob,bobkey)
            for _ in range(80):
                if process.poll() is not None:raise AssertionError("Portal exited")
                try:
                    with alice_client.open(origin+"/api/session",timeout=1):break
                except (OSError,urllib.error.URLError):time.sleep(.25)
            else:raise AssertionError("Portal not ready")
            for c in (client(),client(unknown,unknownkey)):
                try:c.open(origin+"/api/session",timeout=3)
                except (OSError,urllib.error.URLError):pass
                else:raise AssertionError("Unpinned certificate accepted")
            check(True,"no certificate and unknown certificate denied")
            session,_=request(alice_client,"/api/session")
            check(not session["authenticated"],"certificate alone insufficient")
            request(alice_client,"/api/customers",expected=401)
            request(alice_client,"/api/session/login",{"password":passwords["alice"]},expected=403,csrf=False)
            request(alice_client,"/api/session/login",{"password":passwords["bob"]},expected=401)
            _,headers=request(alice_client,"/api/session/login",{"password":passwords["alice"]})
            raw=headers["Set-Cookie"]
            check(all(x.lower() in raw.lower() for x in ("__Host-gc-operator=","secure","httponly","samesite=strict","path=/")),"secure cookie attributes")
            ac=raw.split(";",1)[0]
            request(bob_client,"/api/customers",cookie=ac,expected=401)
            request(alice_client,"/api/customers",cookie=ac)
            request(alice_client,"/api/jobs/00000000-0000-0000-0000-000000000000/decision",{"decision":"approved"},cookie=ac,expected=403)
            _,headers=request(bob_client,"/api/session/login",{"password":passwords["bob"]})
            bc=headers["Set-Cookie"].split(";",1)[0]
            request(bob_client,"/api/customers",{"id":"denied","name":"Denied"},cookie=bc,expected=403)
            request(alice_client,"/api/customers",{"id":"mfa-test","name":"Synthetic MFA Test"},cookie=ac)
            request(alice_client,"/api/session/logout",{},cookie=ac)
            request(alice_client,"/api/customers",cookie=ac,expected=401)
            for _ in range(5):request(alice_client,"/api/session/login",{"password":"incorrect-disposable-password"},expected=401)
            request(alice_client,"/api/session/login",{"password":passwords["alice"]},expected=401)
            check(True,"certificate-bound MFA, RBAC, logout, throttle")
            print("PORTAL_HTTPS_MFA_ACCEPTANCE_PASS",flush=True)
        except Exception:
            out.flush();out.seek(0);print(out.read()[-8000:])
            raise
        finally:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()
