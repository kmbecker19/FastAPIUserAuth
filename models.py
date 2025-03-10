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
    hashed_password: str

class UserUpdate(UserBase):
    username: str | None = None
    email: str | None = None
    full_name: str | None = None
    hashed_password: str | None = None