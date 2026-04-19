from __future__ import annotations

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class PostMessageRequest(BaseModel):
    room: str = Field(min_length=1, max_length=64)
    username: str = Field(min_length=1, max_length=64)
    body: str = Field(min_length=1, max_length=4000)
