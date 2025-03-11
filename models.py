from sqlmodel import Field, SQLModel

# User Models
class UserBase(SQLModel):
    username: str | None = Field(unique=True, primary_key=True)
    email: str | None = Field(unique=True, index=True, default=None)
    full_name: str | None = Field(index=True, default=None)

class User(UserBase, table=True):
    hashed_password: str

class UserPublic(UserBase):
    username: str

class UserCreate(UserBase):
    password: str

class UserUpdate(UserBase):
    username: str | None = None
    email: str | None = None
    full_name: str | None = None
    password: str | None = None

class Token(SQLModel):
    access_token: str = Field(primary_key=True)
    token_type: str = Field(index=True)

class TokenData(SQLModel):
    username: str | None = None