# **学院竞赛管理系统**

## **项目简介**

学院竞赛管理系统旨在帮助学院高效管理学生参与的各类竞赛活动，系统支持竞赛的创建与管理、学生参赛信息的管理与统计、教师指导记录、评委评分管理以及成绩分析和导出功能。系统提供多角色访问，满足管理员、教师、学生不同的使用需求。

---

## **功能特性**

### **1. 用户角色**
- **管理员**：
  - 添加、编辑、删除竞赛。
  - 管理学生、教师和用户账户。
  - 统计比赛数据，生成可视化图表和报表。
- **教师**：
  - 查看指导学生的参赛记录和成绩。
  - 管理学生参赛情况。
- **学生**：
  - 查看自己的参赛记录和成绩。
- **访客**：
  - 浏览公开的比赛信息和获奖名单。

### **2. 系统功能**
- **用户管理**：
  - 用户注册、登录、角色分配。
  - 用户逻辑删除（`is_delete` 标记）。
- **比赛管理**：
  - 比赛的添加、编辑、删除。
  - 批量导入比赛数据（Excel 文件）。
- **参赛信息管理**：
  - 添加和管理学生参赛信息，包括指导老师和比赛结果。
- **数据统计与分析**：
  - 统计参赛人数、指导老师人数、比赛级别和成绩分布。
  - 提供图表（饼图、柱状图）展示统计结果。
- **报表导出**：
  - 导出 Excel 或 PDF 格式的比赛统计数据。
- **评委评分**：
  - 支持评委对学生作品进行评分并记录评语。

---

## **技术栈**

### **前端**
- **框架**：Vue 3
- **状态管理**：Vuex/Pinia
- **路由管理**：Vue Router
- **HTTP 请求**：Axios
- **UI 框架**（可选）：Element Plus / Ant Design Vue / Tailwind CSS

### **后端**
- **框架**：Flask
- **数据库**：MySQL / SQLite（开发环境）
- **ORM**：Flask-SQLAlchemy
- **认证**：Flask-JWT-Extended（基于 JWT 的用户认证）
- **其他**：Flask-CORS、Flask-Bcrypt（密码加密）

### **部署**
- **前端**：Nginx
- **后端**：Gunicorn + Nginx
- **数据库**：MySQL

---

## **项目目录结构**

```
competition-management-system/
│
├── backend/                      # 后端目录
│   ├── app.py                    # 主应用文件
│   ├── models.py                 # 数据库模型定义
│   ├── routes.py                 # API 路由
│   ├── config.py                 # 配置文件（数据库、JWT 等）
│   ├── requirements.txt          # 后端依赖包列表
│   └── migrations/               # 数据库迁移文件
│
├── frontend/                     # 前端目录
│   ├── public/                   # 静态文件
│   ├── src/                      # 源代码
│   │   ├── assets/               # 静态资源
│   │   ├── components/           # Vue 组件
│   │   ├── pages/                # 页面
│   │   ├── router/               # 路由
│   │   ├── store/                # 状态管理
│   │   ├── App.vue               # 主应用组件
│   │   └── main.js               # Vue 启动文件
│   └── package.json              # 前端依赖包列表
│
├── README.md                     # 项目说明文档
└── .gitignore                    # Git 忽略文件
```

---

## **快速开始**

### **1. 克隆项目**
```bash
git clone https://github.com/your-repository/competition-management-system.git
cd competition-management-system
```

### **2. 配置后端**

#### **安装 Python 依赖**
确保 Python 版本为 3.8 或更高：
```bash
cd backend
pip install -r requirements.txt
```

#### **配置数据库**
在 `backend/config.py` 中设置数据库信息：
```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://username:password@localhost/competition_db'
```

#### **初始化数据库**
运行以下命令创建数据库表：
```bash
flask db init
flask db migrate
flask db upgrade
```

#### **启动后端**
```bash
python app.py
```
后端将在 `http://127.0.0.1:5000` 启动。

---

### **3. 配置前端**

#### **安装依赖**
```bash
cd frontend
npm install
```

#### **运行开发服务器**
```bash
npm run serve
```
前端将在 `http://localhost:8080` 启动。

---

### **4. 配置跨域支持**
在后端的 `app.py` 文件中启用 CORS：
```python
from flask_cors import CORS
CORS(app)
```

---

## **API 示例**

### **用户注册**
- **路径**：`POST /api/register`
- **请求体**：
  ```json
  {
    "username": "user1",
    "password": "password123",
    "role": "student",
    "name": "张三",
    "email": "user1@example.com"
  }
  ```
- **响应**：
  ```json
  {"message": "User registered successfully"}
  ```

### **用户登录**
- **路径**：`POST /api/login`
- **请求体**：
  ```json
  {
    "username": "user1",
    "password": "password123"
  }
  ```
- **响应**：
  ```json
  {
    "message": "Login successful",
    "access_token": "jwt-token"
  }
  ```

### **获取比赛列表**
- **路径**：`GET /api/contests`
- **响应**：
  ```json
  [
    {
      "id": 1,
      "name": "数学建模竞赛",
      "category": "国家级",
      "start_time": "2024-01-01T00:00:00",
      "end_time": "2024-01-05T23:59:59"
    }
  ]
  ```

---

## **系统扩展功能**

1. **数据导入与导出**：
   - 支持通过 Excel 文件批量导入学生、比赛数据。
   - 提供数据导出功能，生成 Excel 或 PDF 报表。

2. **数据统计与分析**：
   - 基于 ECharts 或 Chart.js 提供数据可视化图表（如成绩分布、参赛人数统计等）。

3. **实时更新**：
   - 使用 WebSocket 实现比赛进展实时更新（如成绩排名、评分变化）。

4. **通知功能**：
   - 集成邮件服务，比赛状态变更时发送通知。

---

## **常见问题**

1. **如何修改数据库配置？**
   - 修改 `backend/config.py` 中的 `SQLALCHEMY_DATABASE_URI` 配置项。

2. **如何部署到生产环境？**
   - 使用 Gunicorn 部署 Flask 后端：
     ```bash
     gunicorn -w 4 -b 0.0.0.0:5000 app:app
     ```
   - 将前端项目打包部署到 Nginx：
     ```bash
     npm run build
     ```

3. **如何添加新功能？**
   - 后端：在 `routes.py` 中添加新 API，并在 `models.py` 中定义数据表。
   - 前端：在 `src/components/` 或 `src/pages/` 中添加新组件，并更新 `router/index.js`。

---

## **作者与贡献**

- 作者：**Your Name**
- 欢迎贡献代码或提交 Issue！

---

## **许可证**

本项目使用 [MIT License](https://opensource.org/licenses/MIT) 进行许可。

