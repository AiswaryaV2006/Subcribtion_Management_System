import os, re, tempfile
from urllib.parse import unquote
os.environ["DB_URL"] = f"sqlite:///{tempfile.mkdtemp()}/t.db"
from datetime import date
from fastapi.testclient import TestClient
from app.main import app

def test_full_flow(monkeypatch):
    with TestClient(app) as c:
        tok = c.post("/auth/login", json={"email": "admin@brightloop.io", "password": "Admin@12345"}).json()["access_token"]
        H = {"Authorization": f"Bearer {tok}"}
        assert c.get("/plans", headers=H).json() == []
        assert c.post("/auth/signup", json={"email": "a@b.com", "password": "weak"}).status_code == 422
        cu = c.post("/auth/signup", json={"email": "a@b.com", "password": "Strong#Pass1"}).json()
        assert c.post("/auth/signup", json={"email": "a@b.com", "password": "Strong#Pass1"}).status_code == 409
        p = c.post("/products", headers=H, json={"name": "CRM", "sales_price": 1000}).json()
        addon = c.post("/products", headers=H, json={"name": "Priority support", "type": "addon", "sales_price": 25}).json()
        v = c.post("/variants", headers=H, json={"product_id": p["id"], "attribute": "brand", "value": "Odoo", "extra_price": 560}).json()
        pl = c.post("/plans", headers=H, json={"name": "Monthly", "price": 100, "billing_period": "monthly"}).json()
        tx = c.post("/taxes", headers=H, json={"name": "GST", "rate_pct": 18}).json()
        c.post("/discounts", headers=H, json={"name": "10%", "kind": "percent", "value": 10, "usage_limit": 1})
        s = c.post("/subscriptions", headers=H, json={"customer_id": cu["id"], "plan_id": pl["id"], "start_date": str(date.today()),
              "lines": [{"product_id": p["id"], "variant_id": v["id"], "quantity": 1, "tax_id": tx["id"]}]}).json()
        for to in ["quotation", "confirmed", "active"]:
            assert c.post(f"/subscriptions/{s['id']}/transition", headers=H, json={"to": to}).status_code == 200
        assert c.post("/billing/run", headers=H).json()["created"] == 1
        assert c.post("/billing/run", headers=H).json()["created"] == 0   # nothing billed twice
        inv = c.get("/invoices", headers=H).json()[0]
        assert inv["total"] == round((1560 + 100) * 0.9 + 1560 * 0.9 * 0.18, 2)
        c.post(f"/invoices/{inv['id']}/confirm", headers=H)
        assert c.post("/payments", headers=H, json={"invoice_id": inv["id"], "method": "card", "amount": inv["total"]}).status_code == 201
        assert c.get("/reports/summary", headers=H).json()["revenue_collected"] == inv["total"]
        assert c.get("/reports/summary", headers=H).json()["monthly_recurring_revenue"] == 1660

        customer_token = c.post("/auth/login", json={"email": "a@b.com", "password": "Strong#Pass1"}).json()["access_token"]
        customer_headers = {"Authorization": f"Bearer {customer_token}"}
        assert c.get("/auth/me", headers=customer_headers).json()["role"] == "customer"
        assert [plan["id"] for plan in c.get("/plans", headers=customer_headers).json()] == [pl["id"]]
        visible_products = c.get("/products", headers=customer_headers).json()
        assert visible_products[0]["name"] == "CRM"
        assert "cost_price" not in visible_products[0]
        assert c.get("/discounts", headers=customer_headers).status_code == 403
        assert c.get("/invoices", headers=customer_headers).json()[0]["id"] == inv["id"]
        assert c.get(f"/subscriptions/{s['id']}", headers=customer_headers).status_code == 200
        assert c.post(f"/subscriptions/{s['id']}/transition", headers=customer_headers,
                      json={"to": "closed"}).status_code == 403
        assert c.post(f"/subscriptions/{s['id']}/transition", headers=customer_headers,
                      json={"to": "pause"}).status_code == 200
        assert c.post(f"/subscriptions/{s['id']}/transition", headers=customer_headers,
                      json={"to": "resume"}).status_code == 200
        added = c.post(f"/subscriptions/{s['id']}/addons", headers=customer_headers,
                       json={"product_id": addon["id"], "quantity": 1})
        assert added.status_code == 201
        assert added.json()["tax_id"] == tx["id"]
        details = c.get(f"/subscriptions/{s['id']}", headers=customer_headers).json()
        assert len(details["lines"]) == 2
        assert c.delete(f"/subscriptions/{s['id']}/addons/{added.json()['id']}",
                        headers=customer_headers).status_code == 200
        assert len(c.get(f"/subscriptions/{s['id']}", headers=customer_headers).json()["lines"]) == 1
        requested = c.post("/subscriptions", headers=customer_headers,
                           json={"customer_id": cu["id"], "plan_id": pl["id"], "start_date": str(date.today())})
        assert requested.status_code == 201
        assert requested.json()["status"] == "draft"
        customers = c.get("/customers", headers=H).json()
        assert customers[0]["email"] == "a@b.com"
        assert "password_hash" not in customers[0]

        outsider = c.post("/auth/signup", json={"email": "other@b.com", "password": "Strong#Pass1"}).json()
        outsider_token = c.post("/auth/login", json={"email": "other@b.com", "password": "Strong#Pass1"}).json()["access_token"]
        outsider_headers = {"Authorization": f"Bearer {outsider_token}"}
        assert c.get("/invoices", headers=outsider_headers).json() == []
        assert c.get(f"/subscriptions/{s['id']}", headers=outsider_headers).status_code == 404
        assert c.post("/subscriptions", headers=outsider_headers,
                      json={"customer_id": cu["id"], "plan_id": pl["id"], "start_date": str(date.today())}).status_code == 403

        sent_messages = []
        class FakeSMTP:
            def __init__(self, host, port, timeout):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def send_message(self, message):
                sent_messages.append(message)

        monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
        monkeypatch.setenv("SMTP_FROM", "billing@example.test")
        monkeypatch.setenv("SMTP_STARTTLS", "false")
        monkeypatch.setattr("main.smtplib.SMTP", FakeSMTP)
        assert c.post("/auth/forgot", json={"email": "missing@b.com"}).status_code == 200
        assert not sent_messages
        assert c.post("/auth/forgot", json={"email": "a@b.com"}).status_code == 200
        reset_url = re.search(r"reset_token=([^\s&]+)", sent_messages[0].get_content()).group(1)
        reset_token = unquote(reset_url)
        assert c.post("/auth/reset", json={"token": reset_token, "password": "Another#Strong2"}).status_code == 200
        assert c.post("/auth/login", json={"email": "a@b.com", "password": "Another#Strong2"}).status_code == 200
