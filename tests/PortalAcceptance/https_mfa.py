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
    passwords={"alice":base64.b64encode(os.urandom(24)).decode(),"bob":base64.b64encode(os.urandom(24)).decode()}
    def environment(role, name, crt):
        pins=root/(role+"-pins.json"); hashes=root/(role+"-hashes.json")
        pins.write_text(json.dumps({pin(crt):{"id":name,"role":role}}))
        hashes.write_text(json.dumps({name:hash_password(passwords[name])}))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0)); port=sock.getsockname()[1]
        origin=f"https://127.0.0.1:{port}"
        env=os.environ.copy()
        env.update({"ASPNETCORE_URLS":origin,"ASPNETCORE_ENVIRONMENT":"Production",
            "ASPNETCORE_Kestrel__Certificates__Default__Path":str(server),
            "ASPNETCORE_Kestrel__Certificates__Default__KeyPath":str(serverkey),
            "Portal__Origin":origin,"Portal__Role":role,"Portal__OperatorPins":str(pins),
            "Portal__PasswordHashes":str(hashes),
            "ConnectionStrings__Licensing":f"Host=127.0.0.1;Database=gatewaycore_ci;Username=gc_portal_{role};Password=disposable-ci-gc_portal_{role}"})
        return origin,env
    requester,requester_env=environment("requester","alice",alice)
    reviewer,reviewer_env=environment("reviewer","bob",bob)
    command=["dotnet",str(PORTAL/"bin/Release/net10.0/LicensePortal.dll")]
    def rejected_start(env,label):
        result=subprocess.run(command,cwd=PORTAL,env=env,capture_output=True,text=True,timeout=20)
        check(result.returncode!=0 and "InvalidOperationException" in result.stderr,label)
    rejected_start(dict(requester_env,ConnectionStrings__Licensing=reviewer_env["ConnectionStrings__Licensing"]),
                   "requester cannot start with reviewer principal")
    rejected_start(dict(requester_env,ConnectionStrings__LicensingReviewer=reviewer_env["ConnectionStrings__Licensing"]),
                   "legacy dual-credential configuration rejected")
    def client(crt=None,key=None):
        context=ssl.create_default_context(cafile=str(server))
        if crt: context.load_cert_chain(crt,key)
        return urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
    def request(c,origin,path,data=None,cookie=None,expected=200,csrf=True):
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
    with (root/"requester.log").open("w+") as out1,(root/"reviewer.log").open("w+") as out2:
        processes=[subprocess.Popen(command,cwd=PORTAL,env=e,stdout=out,stderr=subprocess.STDOUT)
                   for e,out in ((requester_env,out1),(reviewer_env,out2))]
        try:
            alice_client=client(alice,alicekey);bob_client=client(bob,bobkey)
            for process,c,origin in zip(processes,(alice_client,bob_client),(requester,reviewer)):
                for _ in range(80):
                    if process.poll() is not None:raise AssertionError("Portal exited")
                    try:
                        with c.open(origin+"/api/session",timeout=1):break
                    except (OSError,urllib.error.URLError):time.sleep(.25)
                else:raise AssertionError("Portal not ready")
            for c,origin in ((client(),requester),(client(unknown,unknownkey),requester),
                             (bob_client,requester),(alice_client,reviewer)):
                try:c.open(origin+"/api/session",timeout=3)
                except (OSError,urllib.error.URLError):pass
                else:raise AssertionError("Wrong role/unpinned certificate accepted")
            check(True,"two processes reject certificates from the opposite role")
            def ar(path,**kw):return request(alice_client,requester,path,**kw)
            def br(path,**kw):return request(bob_client,reviewer,path,**kw)
            session,_=ar("/api/session")
            check(not session["authenticated"],"certificate alone insufficient")
            ar("/api/customers",expected=401)
            ar("/api/session/login",data={"password":passwords["alice"]},expected=403,csrf=False)
            ar("/api/session/login",data={"password":passwords["bob"]},expected=401)
            _,headers=ar("/api/session/login",data={"password":passwords["alice"]})
            raw=headers["Set-Cookie"]
            check(all(x.lower() in raw.lower() for x in ("__Host-gc-operator=","secure","httponly","samesite=strict","path=/")),"secure cookie attributes")
            ac=raw.split(";",1)[0]
            br("/api/customers",cookie=ac,expected=401)
            ar("/api/customers",cookie=ac)
            ar("/api/jobs/00000000-0000-0000-0000-000000000000/decision",data={"decision":"approved"},cookie=ac,expected=403)
            _,headers=br("/api/session/login",data={"password":passwords["bob"]})
            bc=headers["Set-Cookie"].split(";",1)[0]
            br("/api/customers",data={"id":"denied","name":"Denied"},cookie=bc,expected=403)
            ar("/api/customers",data={"id":"mfa-test","name":"Synthetic MFA Test"},cookie=ac)
            # Real cross-process decision on a new revocation request. No signing key in either portal.
            job,_=ar("/api/jobs",data={"kind":"revoke","subscriptionId":"ci-license","allocationId":"synthetic-isolation-node"},cookie=ac)
            path="/api/jobs/"+job["id"]+"/decision"
            ar(path,data={"decision":"approved"},cookie=ac,expected=403)
            decision,_=br(path,data={"decision":"approved"},cookie=bc)
            check(decision["state"]=="approved","only independent reviewer process can approve actual pending job")
            br(path,data={"decision":"rejected"},cookie=bc,expected=409)
            ar("/api/session/logout",data={},cookie=ac)
            ar("/api/customers",cookie=ac,expected=401)
            for _ in range(5):ar("/api/session/login",data={"password":"incorrect-disposable-password"},expected=401)
            ar("/api/session/login",data={"password":passwords["alice"]},expected=401)
            check(True,"certificate-bound MFA, separate service RBAC, logout, throttle")
            print("PORTAL_HTTPS_MFA_ACCEPTANCE_PASS",flush=True)
        except Exception:
            for out in (out1,out2):
                out.flush();out.seek(0);print(out.read()[-8000:])
            raise
        finally:
            for process in processes:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()
