from alembic import context


from restoreproof.db.models import Base
from restoreproof.db.session import make_engine

config = context.config
target_metadata = Base.metadata


def run_migrations_online() -> None:
    connectable = config.attributes.get("connection")
    if connectable is not None:
        context.configure(connection=connectable, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = make_engine(config.get_main_option("sqlalchemy.url"))
    with engine.connect() as connection:
        if connection.dialect.name == "postgresql":
            from restoreproof.db.migrations import ADVISORY_LOCK_ID
            connection.exec_driver_sql(f"SELECT pg_advisory_lock({ADVISORY_LOCK_ID})")
            connection.commit()
        sqlite = connection.dialect.name == "sqlite"
        if sqlite:
            # SQLite changes columns by rebuilding the table (copy, drop, rename). With foreign keys enforced the
            # drop fails as soon as other tables reference existing rows, so they are off during migrations
            # and verified afterwards. (The pragma only takes effect outside a transaction.)
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
            # Leftover from a previously interrupted SQLite table rebuild.
            for (name,) in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '_alembic_tmp_%'").all():
                connection.exec_driver_sql(f'DROP TABLE "{name}"')
            connection.commit()
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
        if sqlite:
            problems = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            connection.commit()
            if problems:
                raise RuntimeError(f"migration left {len(problems)} broken references: {problems[:5]}")
    engine.dispose()


run_migrations_online()
