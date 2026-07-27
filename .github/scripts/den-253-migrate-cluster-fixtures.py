from pathlib import Path

path = Path("src/cluster_tests.rs")
source = path.read_text()

customer_old = '''                    "user_id": "00000000-0000-0000-0000-000000000002",
                    "email": "customer@example.com",
                    "roles": ["customer"]'''
customer_new = '''                    "user_id": "00000000-0000-0000-0000-000000000002",
                    "email": "customer@example.com",
                    "roles": ["customer"],
                    "authorization": {
                        "version": 1,
                        "surface_audiences": ["fiducia-customer"],
                        "roles": ["customer"],
                        "capabilities": ["customer:self-service"]
                    }'''
admin_old = '"user": { "user_id": "dev-admin", "email": "op@example.com", "roles": ["admin"] }'
admin_new = '''"user": {
                    "user_id": "dev-admin",
                    "email": "op@example.com",
                    "roles": ["admin"],
                    "authorization": {
                        "version": 1,
                        "surface_audiences": ["fiducia-admin"],
                        "roles": ["admin"],
                        "capabilities": ["admin:read", "admin:operate", "admin:write"]
                    }
                }'''

customer_count = source.count(customer_old)
admin_count = source.count(admin_old)
if customer_count == 0 and admin_count == 0:
    if source.count('"surface_audiences": ["fiducia-admin"]') >= 3 and '"surface_audiences": ["fiducia-customer"]' in source:
        print("cluster authorization fixtures already migrated")
        raise SystemExit(0)
    raise SystemExit("legacy fixture anchors missing without migrated contexts")
if customer_count != 1:
    raise SystemExit(f"expected one customer auth fixture, found {customer_count}")
if admin_count != 3:
    raise SystemExit(f"expected three admin auth fixtures, found {admin_count}")

path.write_text(source.replace(customer_old, customer_new).replace(admin_old, admin_new))
