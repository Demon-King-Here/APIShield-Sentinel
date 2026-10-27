"""Single-operator administration: salted password hashes and revocable sessions."""
import asyncio
import hashlib
import hmac
import ipaddress
import os
import secrets
import time

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.database.db import now

COOKIE='apishield_admin'
IDLE_SECONDS=1800
SESSION_SECONDS=28800


class Credentials(BaseModel):
    model_config=ConfigDict(extra='forbid')
    username: str=Field(min_length=3,max_length=64,pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str=Field(min_length=1,max_length=128)

    @field_validator('username')
    @classmethod
    def normalize(cls,value):
        return value.lower()


class Setup(Credentials):
    setup_code: str=Field(min_length=1,max_length=128)


class PasswordChange(BaseModel):
    model_config=ConfigDict(extra='forbid')
    current_password: str=Field(min_length=1,max_length=128)
    new_password: str=Field(min_length=15,max_length=128)


def local_peer(request):
    try:
        return ipaddress.ip_address(request.client.host).is_loopback
    except (ValueError,AttributeError):
        return False


def password_hash(password,salt=None):
    salt=salt or secrets.token_hex(16)
    value=hashlib.scrypt(password.encode('utf-8'),salt=bytes.fromhex(salt),n=2**17,r=8,p=1,maxmem=256*1024*1024,dklen=32)
    return f'scrypt$131072$8$1${salt}${value.hex()}'


def password_matches(password,stored):
    try:
        algorithm,n,r,p,salt,digest=stored.split('$')
        if (algorithm,n,r,p)!=('scrypt','131072','8','1') or len(salt)!=32 or len(digest)!=64:
            return False
        return hmac.compare_digest(password_hash(password,salt),stored)
    except (ValueError,TypeError):
        return False


def token_hash(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def csrf_token(token):
    return hmac.new(token.encode('utf-8'),b'apishield-admin-csrf',hashlib.sha256).hexdigest()


class Authentication:
    def __init__(self,runtime):
        self.runtime=runtime
        self.db=runtime.db
        self.hash_gate=asyncio.Semaphore(1)
        self.setup_file=self.db.path.parent/'admin-setup-code.txt'
        if not self.account():
            # A fresh code on each unconfigured startup invalidates any old copy.
            code=secrets.token_urlsafe(32)
            self.db.meta('admin_setup_hash',token_hash(code))
            descriptor=os.open(self.setup_file,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(descriptor,'w',encoding='utf-8') as output:
                output.write(code+'\n')
        else:
            self.setup_file.unlink(missing_ok=True)

    def account(self):
        rows=self.db.query('SELECT * FROM admin_accounts WHERE id=1')
        return rows[0] if rows else None

    def throttle(self,request,kind='login'):
        peer=request.client.host if request.client else 'unknown'
        for identity,limit in ((peer,10),('all-clients',50)):
            allowed,retry=self.runtime.limiter.check('__admin_'+kind,identity,limit,900)
            if not allowed:
                raise HTTPException(429,'Too many authentication attempts. Try again later.',headers={'Retry-After':str(retry)})

    async def create_account(self,data,request):
        if not local_peer(request):
            raise HTTPException(403,'First administrator setup requires a loopback connection on this PC')
        self.throttle(request,'setup')
        if self.account():
            raise HTTPException(409,'Administrator is already configured')
        expected=self.db.meta('admin_setup_hash') or ''
        if not expected or not hmac.compare_digest(token_hash(data.setup_code),expected):
            self.db.audit('admin_setup_rejected','Invalid one-time setup code')
            raise HTTPException(401,'Invalid setup code')
        if len(data.password)<15:
            raise HTTPException(422,'Use a password or passphrase of at least 15 characters')
        async with self.hash_gate:
            stored=await asyncio.to_thread(password_hash,data.password)
            with self.db.lock,self.db.conn:
                if self.db.conn.execute('SELECT id FROM admin_accounts').fetchone():
                    raise HTTPException(409,'Administrator is already configured')
                self.db.conn.execute('INSERT INTO admin_accounts VALUES (1,?,?,?)',(data.username,stored,now()))
                self.db.conn.execute('DELETE FROM metadata WHERE key=?',('admin_setup_hash',))
        self.setup_file.unlink(missing_ok=True)
        self.db.audit('administrator_created','Initial administrator configured with a password hash')
        return self.issue(data.username)

    async def login(self,data,request):
        self.throttle(request)
        # A full KDF even for unknown users avoids a cheap username oracle.
        async with self.hash_gate:
            account=self.account()
            stored=account['password_hash'] if account else 'scrypt$131072$8$1$'+('00'*16)+'$'+('00'*32)
            valid=await asyncio.to_thread(password_matches,data.password,stored)
        if not valid or not account or not hmac.compare_digest(data.username,account['username']):
            self.db.audit('admin_login_failed','Invalid administrator credentials')
            raise HTTPException(401,'Invalid username or password')
        self.db.audit('admin_login_success','Administrator signed in')
        return self.issue(account['username'])

    def issue(self,username):
        current=time.time()
        token=secrets.token_urlsafe(32)
        with self.db.lock,self.db.conn:
            self.db.conn.execute('DELETE FROM admin_sessions WHERE expires_at<=? OR last_seen<=?',(current,current-IDLE_SECONDS))
            if self.db.conn.execute('SELECT COUNT(*) FROM admin_sessions').fetchone()[0]>=100:
                raise HTTPException(429,'Session capacity reached; sign out an existing session or wait for expiry')
            self.db.conn.execute('INSERT INTO admin_sessions VALUES (?,?,?,?,?)',(token_hash(token),username,current,current,current+SESSION_SECONDS))
        return token

    def session(self,token,touch=True):
        if not token or len(token)>128:
            return None
        identity=token_hash(token)
        with self.db.lock,self.db.conn:
            row=self.db.conn.execute('SELECT * FROM admin_sessions WHERE token_hash=?',(identity,)).fetchone()
            current=time.time()
            if not row or row['expires_at']<=current or row['last_seen']<=current-IDLE_SECONDS:
                if row:
                    self.db.conn.execute('DELETE FROM admin_sessions WHERE token_hash=?',(identity,))
                return None
            if touch and current-row['last_seen']>=60:
                self.db.conn.execute('UPDATE admin_sessions SET last_seen=? WHERE token_hash=?',(current,identity))
            return dict(row)

    def revoke(self,token):
        self.db.execute('DELETE FROM admin_sessions WHERE token_hash=?',(token_hash(token),))

    async def change_password(self,data,request):
        self.throttle(request,'password')
        async with self.hash_gate:
            account=self.account()
            valid=account and await asyncio.to_thread(password_matches,data.current_password,account['password_hash'])
            if not valid:
                raise HTTPException(401,'Current password is incorrect')
            stored=await asyncio.to_thread(password_hash,data.new_password)
            with self.db.lock,self.db.conn:
                self.db.conn.execute('UPDATE admin_accounts SET password_hash=? WHERE id=1',(stored,))
                self.db.conn.execute('DELETE FROM admin_sessions')
        self.db.audit('admin_password_changed','Administrator password changed; all login sessions revoked')


def set_cookie(response,token,request):
    response.set_cookie(COOKIE,token,max_age=SESSION_SECONDS,httponly=True,secure=request.url.scheme=='https',samesite='strict',path='/api')


def clear_cookie(response):
    response.delete_cookie(COOKIE,path='/api',httponly=True,samesite='strict')
