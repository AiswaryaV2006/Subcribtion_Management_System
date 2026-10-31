# Brightloop Subscription Management System

FastAPI + SQLite platform for subscription catalogues, customer accounts, subscription lifecycle, recurring billing,
invoices, payments and revenue reporting.

Run `pip install -r requirements.txt` and then `uvicorn app.main:app --reload`. Open http://localhost:8000
(API docs at `/docs`). The initial admin is `admin@brightloop.io` / `Admin@12345`; override with `ADMIN_EMAIL` and
`ADMIN_PASSWORD`. Set `JWT_SECRET` to a strong random value before deployment.

The password reset flow sends email using SMTP. Configure `SMTP_HOST`, `SMTP_FROM`, and optionally `SMTP_PORT`
(default `587`), `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_STARTTLS` (default `true`). Set `APP_BASE_URL` to the
public app URL so emailed reset links point to the right host. Reset links expire after 30 minutes.

Customers can register, request subscription plans, see only their own subscriptions and invoices, and pause, resume,
or renew eligible subscriptions. Customers can also add or remove products configured as add-ons; changes apply from
the next invoice. Admins manage the catalogue and create staff accounts; staff handle customer subscriptions, billing
and invoices. Run tests with `pytest`.

Features include products and variants, billing plans, quotation templates, subscriptions, idempotent bulk invoicing,
automatic taxes and discounts, payment tracking, overdue invoices, and `/reports/summary`.
