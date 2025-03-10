from sqlmodel import Field, SQLModel

# User Models
class User(SQLModel):
    username: str | None = Field(primary_key=True)
    email: str | None = Field(default=None)
    full_name: str | None = Field(default=None)

class UserDB(User, table=True):
    hashed_password: str

class UserPublic(User):
    username: str

class UserCreate(User):
    hashed_password: str

class UserUpdate(User):
    username: str | None = None
    email: str | None = None
    full_name: str | None = None
    hashed_password: str | None = None