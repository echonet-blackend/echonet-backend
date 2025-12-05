import os
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from dotenv import load_dotenv

# =========================
# CONFIG
# =========================

load_dotenv()

app = Flask(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///echonet.db")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret-echonet-key")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# allow your GitHub Pages site later – for now allow all
CORS(app, resources={r"/api/*": {"origins": "*"}})


# =========================
# MODELS
# =========================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    display_name = db.Column(db.String(64), nullable=False)
    bio = db.Column(db.Text, default="")
    avatar_url = db.Column(db.String(256), default="")
    banner_url = db.Column(db.String(256), default="")
    is_private = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    posts = db.relationship("Post", backref="author", lazy=True)

    def to_dict(self, include_email=False):
        data = {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name,
            "bio": self.bio or "",
            "avatar_url": self.avatar_url or "",
            "banner_url": self.banner_url or "",
            "is_private": self.is_private,
            "created_at": self.created_at.isoformat(),
        }
        if include_email:
            data["email"] = self.email
        return data


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    media_url = db.Column(db.String(512), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "content": self.content,
            "media_url": self.media_url or "",
            "created_at": self.created_at.isoformat(),
            "author": self.author.to_dict(),
        }


# =========================
# AUTH
# =========================

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    display_name = data.get("display_name") or username

    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "Username or email already taken"}), 400

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    user = User(
        username=username,
        email=email,
        password_hash=pw_hash,
        display_name=display_name,
    )
    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=user.id)
    return jsonify({"token": token, "user": user.to_dict(include_email=True)}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username_or_email = (data.get("username_or_email") or "").strip().lower()
    password = data.get("password") or ""

    if not username_or_email or not password:
        return jsonify({"error": "Missing credentials"}), 400

    user = User.query.filter(
        (User.username == username_or_email) | (User.email == username_or_email)
    ).first()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid username/email or password"}), 401

    token = create_access_token(identity=user.id)
    return jsonify({"token": token, "user": user.to_dict(include_email=True)}), 200


@app.route("/api/me", methods=["GET"])
@jwt_required()
def me():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict(include_email=True)), 200


# =========================
# POSTS / FEED
# =========================

@app.route("/api/posts", methods=["POST"])
@jwt_required()
def create_post():
    user_id = get_jwt_identity()
    data = request.get_json() or {}
    content = (data.get("content") or "").strip()
    media_url = (data.get("media_url") or "").strip()

    if not content and not media_url:
        return jsonify({"error": "Post must have content or media"}), 400

    post = Post(user_id=user_id, content=content, media_url=media_url)
    db.session.add(post)
    db.session.commit()

    return jsonify(post.to_dict()), 201


@app.route("/api/feed", methods=["GET"])
def feed():
    posts = Post.query.order_by(Post.created_at.desc()).limit(50).all()
    return jsonify([p.to_dict() for p in posts]), 200


# =========================
# DB INIT (Render runs this once at start)
# =========================

@app.before_first_request
def init_db():
    db.create_all()


# Local run
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000)
