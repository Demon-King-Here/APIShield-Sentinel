import re
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Policy(BaseModel):
    model_config = ConfigDict(extra='forbid')
    limit: int = Field(default=60, ge=1, le=10000)
    window: int = Field(default=60, ge=1, le=3600)
    max_body: int = Field(default=1048576, ge=0, le=4194304)
    methods: list[str] = Field(default_factory=lambda: ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'], min_length=1, max_length=7)
    allowed_paths: list[str] = Field(default_factory=lambda: ['/'], min_length=1, max_length=30)
    client_key_env: str = ''
    upstream_token_env: str = ''

    @field_validator('methods')
    @classmethod
    def methods_valid(cls, values):
        if any(v not in {'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'} for v in values):
            raise ValueError('Unsupported HTTP method')
        return sorted(set(values))

    @field_validator('allowed_paths')
    @classmethod
    def paths_valid(cls, values):
        if any(not v.startswith('/') or '..' in v or '%' in v or '\\' in v or '?' in v or '#' in v or '//' in v for v in values):
            raise ValueError('Allowed paths must be normalized absolute path prefixes')
        return values

    @field_validator('client_key_env','upstream_token_env')
    @classmethod
    def env_valid(cls, value):
        if value.startswith('APISHIELD_'):
            raise ValueError('APIShield administrative/internal secrets cannot be used as upstream or client credentials')
        if value and not re.fullmatch(r'[A-Z][A-Z0-9_]{2,79}', value):
            raise ValueError('Provide an environment variable name, never a secret value')
        return value


class ServiceInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=80)
    backend_url: str = Field(max_length=200)
    gateway_path: str = Field(pattern=r'^/[a-zA-Z0-9_-]{1,48}$')
    enabled: bool = True
    strip_prefix: bool = True
    health_path: str = Field(default='/health', max_length=200)
    verification_path: str = Field(default='/health', max_length=200)
    timeout: float = Field(default=10, ge=0.1, le=30)
    policy: Policy = Field(default_factory=Policy)

    @field_validator('health_path','verification_path')
    @classmethod
    def safe_path(cls, v):
        if not v.startswith('/') or '//' in v or any(c in v for c in ('..','%','\\','?','#')):
            raise ValueError('Use a normalized path without query parameters')
        return v


