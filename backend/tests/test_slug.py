from conduit.slug import slugify


def test_spaces_and_case():
    assert slugify("Hello World") == "hello-world"


def test_punctuation_is_collapsed():
    assert slugify("  What's new, Conduit?!  ") == "what-s-new-conduit"


def test_accents_are_stripped():
    assert slugify("Café Déjà Vu") == "cafe-deja-vu"


def test_empty_title_gets_fallback():
    assert slugify("!!!") == "article"


def test_length_is_limited_without_trailing_dash():
    slug = slugify("a" * 79 + " b", max_length=80)
    assert len(slug) <= 80
    assert not slug.endswith("-")


def test_created_article_uses_slug(client):
    r = client.post("/api/articles", json={"article": {"title": "Café, Again!", "body": "x"}})
    assert r.status_code == 201
    assert client.get("/api/articles/cafe-again").status_code == 200
