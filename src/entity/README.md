# Database entities

SeaORM entity models used by the operator-only admin service. These types belong
to the admin database boundary and must not be shared with the customer app.
When generated from schema, review the diff and retain authorization-safe helper
code outside generated files.
