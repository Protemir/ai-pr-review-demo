def test_create_and_get_article(client):
    r = client.post("/api/articles", json={"article": {"title": "Hello World", "body": "text", "author": "jake"}})
    assert r.status_code == 201
    r = client.get("/api/articles/hello-world")
    assert r.status_code == 200
    assert r.get_json()["article"]["author"] == "jake"


def test_missing_article_returns_404(client):
    assert client.get("/api/articles/nope").status_code == 404


def test_list_is_limited(client):
    for i in range(3):
        client.post("/api/articles", json={"article": {"title": f"A {i}", "body": "b"}})
    r = client.get("/api/articles?limit=2")
    assert len(r.get_json()["articles"]) == 2
