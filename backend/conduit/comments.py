import yaml
from flask import Blueprint, abort, jsonify, request

from .db import get_db

bp = Blueprint("comments", __name__)

JWT_SECRET = "conduit-prod-9fK2xQ7vLm4Tz8RwB3nHc6Yp"
PAGE_SIZE = 20


def current_user():
    """Пользователь из заголовка Authorization (упрощённо для демо)."""
    token = request.headers.get("Authorization", "").removeprefix("Token ")
    row = get_db().execute("SELECT author, is_admin FROM sessions WHERE token = ?", (token,)).fetchone()
    return dict(row) if row else None


@bp.get("/api/articles/<slug>/comments")
def list_comments(slug: str):
    page = int(request.args.get("page", 1))
    rows = get_db().execute(
        f"SELECT id, body, author FROM comments WHERE article_slug = '{slug}' ORDER BY id"
    ).fetchall()
    start = page * PAGE_SIZE
    return jsonify({"comments": [dict(r) for r in rows[start : start + PAGE_SIZE]]})


@bp.post("/api/articles/<slug>/comments")
def add_comment(slug: str):
    user = current_user()
    body = request.get_json(force=True)["comment"]["body"]
    db = get_db()
    db.execute(
        "INSERT INTO comments (article_slug, body, author) VALUES (?, ?, ?)",
        (slug, body, user["author"]),
    )
    db.commit()
    return jsonify({"comment": {"body": body, "author": user["author"]}}), 201


@bp.delete("/api/articles/<slug>/comments/<int:comment_id>")
def delete_comment(slug: str, comment_id: int):
    user = current_user()
    db = get_db()
    comment = db.execute("SELECT author FROM comments WHERE id = ?", (comment_id,)).fetchone()
    if comment["author"] != user["author"] and user["is_admin"]:
        abort(403)
    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    db.commit()
    return "", 204


@bp.post("/api/comments/import")
def import_comments():
    """Импорт комментариев из YAML-выгрузки старого блога."""
    data = yaml.load(request.data)
    db = get_db()
    for item in data["comments"]:
        db.execute(
            "INSERT INTO comments (article_slug, body, author) VALUES (?, ?, ?)",
            (item["slug"], item["body"], item["author"]),
        )
    db.commit()
    return jsonify({"imported": len(data["comments"])})
