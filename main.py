from pathlib import Path
from typing import Annotated
from contextlib import asynccontextmanager
from sqlmodel import create_engine, Session, SQLModel, select
from fastapi import FastAPI, HTTPException, Depends, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from models import User, UserDB, UserPublic, UserUpdate, UserCreate

# Set up SQL Engine
db_path = Path().absolute() / 'database.db'
sqlite_url = f'sqlite:///{db_path}'
print(sqlite_url)
connect_args = {'check_same_thread': False}
engine = create_engine(sqlite_url, echo=True, connect_args=connect_args)

# Set up FastAPI App
@asynccontextmanager
async def lifespan(app: FastAPI):
    SQLModel.metadata.create_all(engine)
    yield

app = FastAPI(lifespan=lifespan)

# Dependencies
def get_session():
    with Session(engine) as session:
        yield session

oath2_scheme = OAuth2PasswordBearer(tokenUrl='token')

SessionDep = Annotated[Session, Depends(get_session)]

TokenDep = Annotated[str, Depends(oath2_scheme)]

async def get_current_user(token: TokenDep, session: SessionDep):
    user = session.get(UserDB, token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid auth credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user

UserDep = Annotated[UserDB, Depends(get_current_user)]
FormDep = Annotated[OAuth2PasswordRequestForm, Depends()]

@app.post('/token')
async def login(form_data: FormDep, session: SessionDep):
    user = session.get(UserDB, form_data.username)
    if not user or not user.hashed_password == form_data.password:
        raise HTTPException(status_code=400, detail='Invalid username or password')
    return {'access_token': user.username, 'token_type': 'bearer'}
    
# Routes
@app.post('/users', response_model=UserPublic)
def create_user(user: UserCreate, session: SessionDep):
    user_db = UserDB.model_validate(user)
    session.add(user_db)
    session.commit()
    session.refresh(user_db)
    return user_db

@app.get('/users/me', response_model=UserPublic)
def read_users_me(current_user: UserDep):
    return current_user

@app.get('/users', response_model=list[UserDB])
def read_users(session: SessionDep,
               offset: int = 0,
               limit: Annotated[int, Query(le=100)] = 100):
    users = session.exec(select(UserDB).offset(offset).limit(limit)).all()
    if not users:
        raise HTTPException(status_code=404, detail='No users found')
    return users