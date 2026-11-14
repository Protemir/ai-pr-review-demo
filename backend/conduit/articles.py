from flask import Blueprint, abort, jsonify, request

from .db import get_db
from .slug import slugify

bp = Blueprint("articles", __name__)


@bp.get("/api/articles")
def list_articles():
    limit = min(int(request.args.get("limit", 20)), 100)
    offset = int(request.args.get("offset", 0))
    rows = get_db().execute(
        "SELECT slug, title, author FROM articles ORDER BY slug LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    return jsonify({"articles": [dict(r) for r in rows], "articlesCount": len(rows)})


@bp.get("/api/articles/<slug>")
def get_article(slug: str):
    row = get_db().execute("SELECT * FROM articles WHERE slug = ?", (slug,)).fetchone()
    if row is None:
        abort(404)
    return jsonify({"article": dict(row)})


@bp.post("/api/articles")
def create_article():
    data = request.get_json(force=True)["article"]
    db = get_db()
    db.execute(
        "INSERT INTO articles (slug, title, body, author) VALUES (?, ?, ?, ?)",
        (slugify(data["title"]), data["title"], data["body"], data.get("author", "anonymous")),
    )
    db.commit()
    return jsonify({"article": data}), 201
