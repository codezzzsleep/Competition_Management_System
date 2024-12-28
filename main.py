# main.py

import uuid
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import (
    Column,
    String,
    Enum,
    Boolean,
    DateTime,
    ForeignKey,
    Float,
    Table,
    Text,
    create_engine,
    func,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
from pydantic import BaseModel
import enum
import pandas as pd

# ---------------------- 配置部分 ----------------------

#mysql配置

# 创建数据库引擎
engine = create_engine(DATABASE_URL, echo=True, pool_pre_ping=True)

# 创建SessionLocal类
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 创建基类
Base = declarative_base()

# 创建FastAPI实例
app = FastAPI(title="竞赛记录管理系统")

# 密码哈希上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2密码认证
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# JWT配置
SECRET_KEY = "your_secret_key"  # 请替换为安全的密钥
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24小时

# ---------------------- 模型部分 ----------------------

# 用户角色枚举
class RoleEnum(str, enum.Enum):
    super_admin = "超级管理员"
    admin = "管理员"
    student = "学生"

# 竞赛类型枚举
class CompetitionTypeEnum(str, enum.Enum):
    team = "团队赛"
    individual = "个人赛"

# 报名状态枚举
class ApplicationStatusEnum(str, enum.Enum):
    registered = "已报名"
    submitted = "已提交作品"
    ended = "已结束"

# 竞赛类别枚举
class CompetitionCategoryEnum(str, enum.Enum):
    category1 = "一类"
    category2 = "二类"
    category3 = "三类"

# 竞赛级别枚举
class CompetitionLevelEnum(str, enum.Enum):
    school = "校级"
    province = "省级"
    national = "国家级"

# 用户表
class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=True, index=True)
    password = Column(String(255), nullable=False)
    role = Column(Enum(RoleEnum), default=RoleEnum.student, nullable=False)
    group_id = Column(String(36), ForeignKey("groups.id"), nullable=True)
    is_delete = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    group = relationship("Group", back_populates="members")
    applications = relationship("Application", back_populates="user")
    notifications = relationship("Notification", back_populates="recipient")
    logs = relationship("Log", back_populates="user")

# 组表
class Group(Base):
    __tablename__ = "groups"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    is_delete = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    members = relationship("User", back_populates="group")
    competitions = relationship("Competition", secondary="competition_groups", back_populates="groups")

# 竞赛类别表
class CompetitionCategory(Base):
    __tablename__ = "competition_categories"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, index=True)
    name = Column(String(50), unique=True, nullable=False)

    competitions = relationship("Competition", back_populates="category_obj")

# 竞赛级别表
class CompetitionLevel(Base):
    __tablename__ = "competition_levels"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, index=True)
    name = Column(String(50), unique=True, nullable=False)

    competitions = relationship("Competition", back_populates="level_obj")

# 竞赛表
class Competition(Base):
    __tablename__ = "competitions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, index=True)
    name = Column(String(255), nullable=False)
    category_id = Column(String(36), ForeignKey("competition_categories.id"), nullable=False)
    level_id = Column(String(36), ForeignKey("competition_levels.id"), nullable=False)
    type = Column(Enum(CompetitionTypeEnum), nullable=False)
    registration_deadline = Column(DateTime, nullable=False)
    submission_deadline = Column(DateTime, nullable=False)
    website = Column(String(255), nullable=True)
    video_url = Column(String(255), nullable=True)
    files = Column(Text, nullable=True)
    remarks = Column(Text, nullable=True)
    is_delete = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    groups = relationship("Group", secondary="competition_groups", back_populates="competitions")
    category_obj = relationship("CompetitionCategory", back_populates="competitions")
    level_obj = relationship("CompetitionLevel", back_populates="competitions")
    applications = relationship("Application", back_populates="competition")

# 竞赛与组的多对多关联表
competition_groups = Table(
    "competition_groups",
    Base.metadata,
    Column("competition_id", String(36), ForeignKey("competitions.id"), primary_key=True),
    Column("group_id", String(36), ForeignKey("groups.id"), primary_key=True),
)

# 报名表
class Application(Base):
    __tablename__ = "applications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, index=True)
    competition_id = Column(String(36), ForeignKey("competitions.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    team_name = Column(String(255), nullable=True)
    application_status = Column(Enum(ApplicationStatusEnum), default=ApplicationStatusEnum.registered, nullable=False)
    submission_url = Column(String(255), nullable=True)
    award_url = Column(String(255), nullable=True)
    score = Column(Float, nullable=True)
    is_delete = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    competition = relationship("Competition", back_populates="applications")
    user = relationship("User", back_populates="applications")

# 消息通知表
class Notification(Base):
    __tablename__ = "notifications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, index=True)
    recipient_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    read = Column(Boolean, default=False)

    recipient = relationship("User", back_populates="notifications")

# 操作日志表
class Log(Base):
    __tablename__ = "logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    action = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="logs")

# 创建所有表
Base.metadata.create_all(bind=engine)

# ---------------------- Pydantic Schemas ----------------------

# 用户相关
class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    role: RoleEnum
    group_id: Optional[uuid.UUID]
    created_at: datetime

    class Config:
        orm_mode = True

# Token相关
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# 组相关
class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None

class GroupResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    created_at: datetime

    class Config:
        orm_mode = True

# 竞赛类别相关
class CompetitionCategoryCreate(BaseModel):
    name: str

class CompetitionCategoryResponse(BaseModel):
    id: uuid.UUID
    name: str

    class Config:
        orm_mode = True

# 竞赛级别相关
class CompetitionLevelCreate(BaseModel):
    name: str

class CompetitionLevelResponse(BaseModel):
    id: uuid.UUID
    name: str

    class Config:
        orm_mode = True

# 竞赛相关
class CompetitionCreate(BaseModel):
    name: str
    category_id: uuid.UUID
    level_id: uuid.UUID
    type: CompetitionTypeEnum
    registration_deadline: datetime
    submission_deadline: datetime
    website: Optional[str] = None
    video_url: Optional[str] = None
    files: Optional[str] = None
    remarks: Optional[str] = None
    group_ids: List[uuid.UUID]

class CompetitionResponse(BaseModel):
    id: uuid.UUID
    name: str
    category_id: uuid.UUID
    category: CompetitionCategoryResponse
    level_id: uuid.UUID
    level: CompetitionLevelResponse
    type: CompetitionTypeEnum
    registration_deadline: datetime
    submission_deadline: datetime
    website: Optional[str]
    video_url: Optional[str]
    files: Optional[str]
    remarks: Optional[str]
    group_ids: List[uuid.UUID]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

# 报名相关
class ApplicationCreate(BaseModel):
    competition_id: uuid.UUID
    user_id: uuid.UUID
    team_name: Optional[str] = None

class ApplicationResponse(BaseModel):
    id: uuid.UUID
    competition_id: uuid.UUID
    user_id: uuid.UUID
    team_name: Optional[str]
    application_status: ApplicationStatusEnum
    submission_url: Optional[str]
    award_url: Optional[str]
    score: Optional[float]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class ApplicationUpload(BaseModel):
    submission_url: Optional[str] = None
    award_url: Optional[str] = None

# 消息通知相关
class NotificationCreate(BaseModel):
    recipient_id: uuid.UUID
    content: str

class NotificationResponse(BaseModel):
    id: uuid.UUID
    recipient_id: uuid.UUID
    content: str
    timestamp: datetime
    read: bool

    class Config:
        orm_mode = True

# 数据统计相关
class CompetitionStatistics(BaseModel):
    category: str
    level: str
    total_competitions: int

class UserStatistics(BaseModel):
    role: RoleEnum
    total_users: int

class GroupStatistics(BaseModel):
    group_id: uuid.UUID
    group_name: str
    total_members: int

# 系统设置相关
class OperationLogResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    action: str
    timestamp: datetime

    class Config:
        orm_mode = True

# ---------------------- 认证相关 ----------------------

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username, User.is_delete == False).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(lambda: SessionLocal())):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭证",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.is_delete:
        raise HTTPException(status_code=400, detail="用户已禁用")
    return current_user

# ---------------------- 依赖注入 ----------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------- 路由部分 ----------------------

# ---------------------- 1. 用户管理模块 ----------------------

@app.post("/api/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username, User.is_delete == False).first()
    if db_user:
        raise HTTPException(status_code=400, detail="用户名已存在")
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, password=hashed_password, role=RoleEnum.student)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/users/{id}", response_model=UserResponse)
def get_user_info(id: uuid.UUID, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == str(id), User.is_delete == False).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户未找到")
    return user

@app.get("/api/users", response_model=List[UserResponse])
def get_all_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role not in [RoleEnum.admin, RoleEnum.super_admin]:
        raise HTTPException(status_code=403, detail="无权限访问")
    users = db.query(User).filter(User.is_delete == False).all()
    return users

# ---------------------- 2. 组管理模块 ----------------------

@app.post("/api/groups", response_model=GroupResponse, status_code=status.HTTP_201_CREATED)
def create_group(group: GroupCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role not in [RoleEnum.admin, RoleEnum.super_admin]:
        raise HTTPException(status_code=403, detail="无权限创建组")
    db_group = db.query(Group).filter(Group.name == group.name, Group.is_delete == False).first()
    if db_group:
        raise HTTPException(status_code=400, detail="组名已存在")
    new_group = Group(name=group.name, description=group.description)
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    return new_group

@app.get("/api/groups", response_model=List[GroupResponse])
def get_groups(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    groups = db.query(Group).filter(Group.is_delete == False).all()
    return groups

@app.post("/api/groups/{group_id}/add_user", status_code=status.HTTP_200_OK)
def add_user_to_group(group_id: uuid.UUID, user_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role not in [RoleEnum.admin, RoleEnum.super_admin]:
        raise HTTPException(status_code=403, detail="无权限添加用户到组")
    group = db.query(Group).filter(Group.id == str(group_id), Group.is_delete == False).first()
    if not group:
        raise HTTPException(status_code=404, detail="组未找到")
    user = db.query(User).filter(User.id == str(user_id), User.is_delete == False).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户未找到")
    user.group_id = str(group_id)
    db.commit()
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"添加用户(ID: {user_id})到组(ID: {group_id})")
    db.add(log)
    db.commit()
    return {"group_id": group_id, "user_id": user_id, "message": "用户已成功添加到组。"}

@app.delete("/api/groups/{group_id}/remove_user", status_code=status.HTTP_200_OK)
def remove_user_from_group(group_id: uuid.UUID, user_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role not in [RoleEnum.admin, RoleEnum.super_admin]:
        raise HTTPException(status_code=403, detail="无权限移除用户从组")
    group = db.query(Group).filter(Group.id == str(group_id), Group.is_delete == False).first()
    if not group:
        raise HTTPException(status_code=404, detail="组未找到")
    user = db.query(User).filter(User.id == str(user_id), User.group_id == str(group_id), User.is_delete == False).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户未找到或不属于该组")
    user.group_id = None
    db.commit()
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"移除用户(ID: {user_id})从组(ID: {group_id})")
    db.add(log)
    db.commit()
    return {"group_id": group_id, "user_id": user_id, "message": "用户已成功移除出组。"}

@app.get("/api/groups/{group_id}/users", response_model=List[UserResponse])
def get_users_in_group(group_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    group = db.query(Group).filter(Group.id == str(group_id), Group.is_delete == False).first()
    if not group:
        raise HTTPException(status_code=404, detail="组未找到")
    # 权限检查：管理员只能查看自己负责的组
    if current_user.role == RoleEnum.admin and current_user.group_id != str(group_id):
        raise HTTPException(status_code=403, detail="无权限查看该组的用户")
    users = db.query(User).filter(User.group_id == str(group_id), User.is_delete == False).all()
    return users

# ---------------------- 3. 竞赛管理模块 ----------------------

@app.post("/api/competitions", response_model=CompetitionResponse, status_code=status.HTTP_201_CREATED)
def create_competition(competition: CompetitionCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role not in [RoleEnum.admin, RoleEnum.super_admin]:
        raise HTTPException(status_code=403, detail="无权限创建竞赛")
    # 检查竞赛类别和级别是否存在
    category = db.query(CompetitionCategory).filter(CompetitionCategory.id == str(competition.category_id)).first()
    if not category:
        raise HTTPException(status_code=400, detail="竞赛类别不存在")
    level = db.query(CompetitionLevel).filter(CompetitionLevel.id == str(competition.level_id)).first()
    if not level:
        raise HTTPException(status_code=400, detail="竞赛级别不存在")
    new_competition = Competition(
        name=competition.name,
        category_id=str(competition.category_id),
        level_id=str(competition.level_id),
        type=competition.type,
        registration_deadline=competition.registration_deadline,
        submission_deadline=competition.submission_deadline,
        website=competition.website,
        video_url=competition.video_url,
        files=competition.files,
        remarks=competition.remarks,
    )
    # 关联组
    groups = db.query(Group).filter(Group.id.in_([str(gid) for gid in competition.group_ids]), Group.is_delete == False).all()
    if not groups:
        raise HTTPException(status_code=400, detail="指定的组不存在")
    new_competition.groups.extend(groups)
    db.add(new_competition)
    db.commit()
    db.refresh(new_competition)
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"创建竞赛(ID: {new_competition.id}, 名称: {new_competition.name})")
    db.add(log)
    db.commit()
    return CompetitionResponse(
        id=new_competition.id,
        name=new_competition.name,
        category_id=new_competition.category_id,
        category=CompetitionCategoryResponse(id=category.id, name=category.name),
        level_id=new_competition.level_id,
        level=CompetitionLevelResponse(id=level.id, name=level.name),
        type=new_competition.type,
        registration_deadline=new_competition.registration_deadline,
        submission_deadline=new_competition.submission_deadline,
        website=new_competition.website,
        video_url=new_competition.video_url,
        files=new_competition.files,
        remarks=new_competition.remarks,
        group_ids=[uuid.UUID(group.id) for group in new_competition.groups],
        created_at=new_competition.created_at,
        updated_at=new_competition.updated_at,
    )

@app.get("/api/competitions", response_model=List[CompetitionResponse])
def get_competitions(group_id: Optional[uuid.UUID] = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    query = db.query(Competition).filter(Competition.is_delete == False)
    if group_id:
        query = query.join(competition_groups).filter(competition_groups.c.group_id == str(group_id))
    competitions = query.all()
    response = []
    for comp in competitions:
        response.append(CompetitionResponse(
            id=comp.id,
            name=comp.name,
            category_id=comp.category_id,
            category=CompetitionCategoryResponse(id=comp.category_obj.id, name=comp.category_obj.name),
            level_id=comp.level_id,
            level=CompetitionLevelResponse(id=comp.level_obj.id, name=comp.level_obj.name),
            type=comp.type,
            registration_deadline=comp.registration_deadline,
            submission_deadline=comp.submission_deadline,
            website=comp.website,
            video_url=comp.video_url,
            files=comp.files,
            remarks=comp.remarks,
            group_ids=[uuid.UUID(group.id) for group in comp.groups],
            created_at=comp.created_at,
            updated_at=comp.updated_at,
        ))
    return response

@app.get("/api/competitions/{id}", response_model=CompetitionResponse)
def get_competition_detail(id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    comp = db.query(Competition).filter(Competition.id == str(id), Competition.is_delete == False).first()
    if not comp:
        raise HTTPException(status_code=404, detail="竞赛未找到")
    category = db.query(CompetitionCategory).filter(CompetitionCategory.id == comp.category_id).first()
    level = db.query(CompetitionLevel).filter(CompetitionLevel.id == comp.level_id).first()
    return CompetitionResponse(
        id=comp.id,
        name=comp.name,
        category_id=comp.category_id,
        category=CompetitionCategoryResponse(id=category.id, name=category.name),
        level_id=comp.level_id,
        level=CompetitionLevelResponse(id=level.id, name=level.name),
        type=comp.type,
        registration_deadline=comp.registration_deadline,
        submission_deadline=comp.submission_deadline,
        website=comp.website,
        video_url=comp.video_url,
        files=comp.files,
        remarks=comp.remarks,
        group_ids=[uuid.UUID(group.id) for group in comp.groups],
        created_at=comp.created_at,
        updated_at=comp.updated_at,
    )

# ---------------------- 4. 报名管理模块 ----------------------

@app.post("/api/applications", response_model=ApplicationResponse, status_code=status.HTTP_201_CREATED)
def submit_application(application: ApplicationCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    # 确保用户ID与当前用户匹配，或者当前用户有权限为其他用户报名
    if application.user_id != current_user.id and current_user.role != RoleEnum.super_admin:
        raise HTTPException(status_code=403, detail="无权限为其他用户报名")
    # 检查竞赛是否存在
    competition = db.query(Competition).filter(Competition.id == str(application.competition_id), Competition.is_delete == False).first()
    if not competition:
        raise HTTPException(status_code=404, detail="竞赛未找到")
    # 检查报名截止时间
    if datetime.utcnow() > competition.registration_deadline:
        raise HTTPException(status_code=400, detail="报名截止时间已过")
    # 检查是否已经报名
    existing_application = db.query(Application).filter(
        Application.competition_id == str(application.competition_id),
        Application.user_id == str(application.user_id),
        Application.is_delete == False
    ).first()
    if existing_application:
        raise HTTPException(status_code=400, detail="已经报名过该竞赛")
    # 创建报名记录
    new_application = Application(
        competition_id=str(application.competition_id),
        user_id=str(application.user_id),
        team_name=application.team_name,
        application_status=ApplicationStatusEnum.registered
    )
    db.add(new_application)
    db.commit()
    db.refresh(new_application)
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"用户(ID: {application.user_id})报名竞赛(ID: {application.competition_id})")
    db.add(log)
    db.commit()
    return ApplicationResponse(
        id=new_application.id,
        competition_id=new_application.competition_id,
        user_id=new_application.user_id,
        team_name=new_application.team_name,
        application_status=new_application.application_status,
        submission_url=new_application.submission_url,
        award_url=new_application.award_url,
        score=new_application.score,
        created_at=new_application.created_at,
        updated_at=new_application.updated_at,
    )

@app.get("/api/applications", response_model=List[ApplicationResponse])
def get_applications(competition_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    # 检查竞赛是否存在
    competition = db.query(Competition).filter(Competition.id == str(competition_id), Competition.is_delete == False).first()
    if not competition:
        raise HTTPException(status_code=404, detail="竞赛未找到")
    # 权限检查：管理员只能查看自己组的竞赛
    if current_user.role == RoleEnum.admin and current_user.group_id not in [group.id for group in competition.groups]:
        raise HTTPException(status_code=403, detail="无权限查看该竞赛的报名记录")
    applications = db.query(Application).filter(Application.competition_id == str(competition_id), Application.is_delete == False).all()
    response = []
    for app_record in applications:
        response.append(ApplicationResponse(
            id=app_record.id,
            competition_id=uuid.UUID(app_record.competition_id),
            user_id=uuid.UUID(app_record.user_id),
            team_name=app_record.team_name,
            application_status=app_record.application_status,
            submission_url=app_record.submission_url,
            award_url=app_record.award_url,
            score=app_record.score,
            created_at=app_record.created_at,
            updated_at=app_record.updated_at,
        ))
    return response

@app.post("/api/applications/{id}/upload", response_model=ApplicationResponse)
def upload_application(id: uuid.UUID, upload: ApplicationUpload, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    application = db.query(Application).filter(Application.id == str(id), Application.is_delete == False).first()
    if not application:
        raise HTTPException(status_code=404, detail="报名记录未找到")
    if application.user_id != str(current_user.id) and current_user.role != RoleEnum.super_admin:
        raise HTTPException(status_code=403, detail="无权限上传作品或奖状")
    # 更新提交状态
    if upload.submission_url:
        application.submission_url = upload.submission_url
        application.application_status = ApplicationStatusEnum.submitted
    if upload.award_url:
        application.award_url = upload.award_url
    db.commit()
    db.refresh(application)
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"用户(ID: {application.user_id})上传作品或奖状到报名记录(ID: {id})")
    db.add(log)
    db.commit()
    return ApplicationResponse(
        id=application.id,
        competition_id=uuid.UUID(application.competition_id),
        user_id=uuid.UUID(application.user_id),
        team_name=application.team_name,
        application_status=application.application_status,
        submission_url=application.submission_url,
        award_url=application.award_url,
        score=application.score,
        created_at=application.created_at,
        updated_at=application.updated_at,
    )

# ---------------------- 5. 数据统计与分析模块 ----------------------

@app.get("/api/statistics/competitions", response_model=List[CompetitionStatistics])
def get_competition_statistics(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    stats = db.query(
        CompetitionCategory.name.label("category"),
        CompetitionLevel.name.label("level"),
        func.count(Competition.id).label("total_competitions")
    ).join(Competition.category_obj).join(Competition.level_obj).group_by(CompetitionCategory.name, CompetitionLevel.name).all()
    
    return [CompetitionStatistics(category=stat.category, level=stat.level, total_competitions=stat.total_competitions) for stat in stats]

@app.get("/api/statistics/users", response_model=List[UserStatistics])
def get_user_statistics(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    stats = db.query(
        User.role,
        func.count(User.id).label("total_users")
    ).filter(User.is_delete == False).group_by(User.role).all()
    
    return [UserStatistics(role=stat.role, total_users=stat.total_users) for stat in stats]

@app.get("/api/statistics/groups", response_model=List[GroupStatistics])
def get_group_statistics(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    stats = db.query(
        Group.id.label("group_id"),
        Group.name.label("group_name"),
        func.count(User.id).label("total_members")
    ).join(Group.members).filter(User.is_delete == False).group_by(Group.id, Group.name).all()
    
    return [GroupStatistics(group_id=uuid.UUID(stat.group_id), group_name=stat.group_name, total_members=stat.total_members) for stat in stats]

@app.get("/api/statistics/export", response_model=dict)
def export_statistics(format: str = "csv", db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if format not in ["csv", "excel"]:
        raise HTTPException(status_code=400, detail="格式不支持。仅支持 'csv' 和 'excel'。")
    
    # 获取竞赛统计
    competition_stats = db.query(
        CompetitionCategory.name.label("Category"),
        CompetitionLevel.name.label("Level"),
        func.count(Competition.id).label("Total Competitions")
    ).join(Competition.category_obj).join(Competition.level_obj).group_by(CompetitionCategory.name, CompetitionLevel.name).all()
    
    df = pd.DataFrame(competition_stats, columns=["Category", "Level", "Total Competitions"])
    
    if format == "csv":
        csv_data = df.to_csv(index=False)
        return {"data": csv_data, "format": "csv"}
    else:
        excel_path = f"competition_statistics_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.xlsx"
        df.to_excel(excel_path, index=False)
        return {"data": f"文件已保存到服务器：{excel_path}", "format": "excel"}

# ---------------------- 6. 消息通知模块 ----------------------

@app.post("/api/notifications/send", status_code=status.HTTP_201_CREATED)
def send_notification(notification: NotificationCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role not in [RoleEnum.admin, RoleEnum.super_admin]:
        raise HTTPException(status_code=403, detail="无权限发送通知")
    recipient = db.query(User).filter(User.id == str(notification.recipient_id), User.is_delete == False).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="收件人未找到")
    new_notification = Notification(
        recipient_id=str(notification.recipient_id),
        content=notification.content
    )
    db.add(new_notification)
    db.commit()
    db.refresh(new_notification)
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"发送通知(ID: {new_notification.id})给用户(ID: {notification.recipient_id})")
    db.add(log)
    db.commit()
    return {"id": new_notification.id, "message": "通知已发送"}

@app.get("/api/notifications", response_model=List[NotificationResponse])
def get_notifications(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    notifications = db.query(Notification).filter(Notification.recipient_id == str(current_user.id), Notification.is_delete == False).all()
    return notifications

@app.put("/api/notifications/{id}/read", response_model=NotificationResponse)
def mark_notification_as_read(id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    notification = db.query(Notification).filter(Notification.id == str(id), Notification.recipient_id == str(current_user.id), Notification.is_delete == False).first()
    if not notification:
        raise HTTPException(status_code=404, detail="通知未找到")
    notification.read = True
    db.commit()
    db.refresh(notification)
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"标记通知(ID: {id})为已读")
    db.add(log)
    db.commit()
    return notification

# ---------------------- 7. 系统设置模块 ----------------------

# 竞赛类别管理
@app.post("/api/settings/competition_categories", response_model=CompetitionCategoryResponse, status_code=status.HTTP_201_CREATED)
def create_competition_category(category: CompetitionCategoryCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != RoleEnum.super_admin:
        raise HTTPException(status_code=403, detail="无权限创建竞赛类别")
    db_category = db.query(CompetitionCategory).filter(CompetitionCategory.name == category.name).first()
    if db_category:
        raise HTTPException(status_code=400, detail="竞赛类别已存在")
    new_category = CompetitionCategory(name=category.name)
    db.add(new_category)
    db.commit()
    db.refresh(new_category)
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"创建竞赛类别(ID: {new_category.id}, 名称: {new_category.name})")
    db.add(log)
    db.commit()
    return new_category

@app.get("/api/settings/competition_categories", response_model=List[CompetitionCategoryResponse])
def get_competition_categories(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    categories = db.query(CompetitionCategory).all()
    return categories

@app.put("/api/settings/competition_categories/{id}", response_model=CompetitionCategoryResponse)
def update_competition_category(id: uuid.UUID, category: CompetitionCategoryCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != RoleEnum.super_admin:
        raise HTTPException(status_code=403, detail="无权限更新竞赛类别")
    db_category = db.query(CompetitionCategory).filter(CompetitionCategory.id == str(id)).first()
    if not db_category:
        raise HTTPException(status_code=404, detail="竞赛类别未找到")
    db_category.name = category.name
    db.commit()
    db.refresh(db_category)
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"更新竞赛类别(ID: {id}, 新名称: {category.name})")
    db.add(log)
    db.commit()
    return db_category

@app.delete("/api/settings/competition_categories/{id}", status_code=status.HTTP_200_OK)
def delete_competition_category(id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != RoleEnum.super_admin:
        raise HTTPException(status_code=403, detail="无权限删除竞赛类别")
    db_category = db.query(CompetitionCategory).filter(CompetitionCategory.id == str(id)).first()
    if not db_category:
        raise HTTPException(status_code=404, detail="竞赛类别未找到")
    db.delete(db_category)
    db.commit()
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"删除竞赛类别(ID: {id})")
    db.add(log)
    db.commit()
    return {"message": "竞赛类别已删除"}

# 竞赛级别管理
@app.post("/api/settings/competition_levels", response_model=CompetitionLevelResponse, status_code=status.HTTP_201_CREATED)
def create_competition_level(level: CompetitionLevelCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != RoleEnum.super_admin:
        raise HTTPException(status_code=403, detail="无权限创建竞赛级别")
    db_level = db.query(CompetitionLevel).filter(CompetitionLevel.name == level.name).first()
    if db_level:
        raise HTTPException(status_code=400, detail="竞赛级别已存在")
    new_level = CompetitionLevel(name=level.name)
    db.add(new_level)
    db.commit()
    db.refresh(new_level)
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"创建竞赛级别(ID: {new_level.id}, 名称: {new_level.name})")
    db.add(log)
    db.commit()
    return new_level

@app.get("/api/settings/competition_levels", response_model=List[CompetitionLevelResponse])
def get_competition_levels(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    levels = db.query(CompetitionLevel).all()
    return levels

@app.put("/api/settings/competition_levels/{id}", response_model=CompetitionLevelResponse)
def update_competition_level(id: uuid.UUID, level: CompetitionLevelCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != RoleEnum.super_admin:
        raise HTTPException(status_code=403, detail="无权限更新竞赛级别")
    db_level = db.query(CompetitionLevel).filter(CompetitionLevel.id == str(id)).first()
    if not db_level:
        raise HTTPException(status_code=404, detail="竞赛级别未找到")
    db_level.name = level.name
    db.commit()
    db.refresh(db_level)
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"更新竞赛级别(ID: {id}, 新名称: {level.name})")
    db.add(log)
    db.commit()
    return db_level

@app.delete("/api/settings/competition_levels/{id}", status_code=status.HTTP_200_OK)
def delete_competition_level(id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != RoleEnum.super_admin:
        raise HTTPException(status_code=403, detail="无权限删除竞赛级别")
    db_level = db.query(CompetitionLevel).filter(CompetitionLevel.id == str(id)).first()
    if not db_level:
        raise HTTPException(status_code=404, detail="竞赛级别未找到")
    db.delete(db_level)
    db.commit()
    # 记录操作日志
    log = Log(user_id=current_user.id, action=f"删除竞赛级别(ID: {id})")
    db.add(log)
    db.commit()
    return {"message": "竞赛级别已删除"}

# ---------------------- 8. 操作日志模块 ----------------------

@app.get("/api/logs", response_model=List[OperationLogResponse])
def get_operation_logs(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != RoleEnum.super_admin:
        raise HTTPException(status_code=403, detail="无权限查看操作日志")
    logs = db.query(Log).order_by(Log.timestamp.desc()).all()
    return logs

# ---------------------- 启动命令 ----------------------

# 运行命令: uvicorn main:app --reload
