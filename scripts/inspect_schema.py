from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import inspect, text

from app import create_app
from app.extensions import db

app = create_app()

with app.app_context():
    engine = db.engine
    print("Database dialect:", engine.dialect.name)

    with engine.connect() as connection:
        result = connection.execute(text("SELECT 1 FROM DUAL"))
        print("Oracle connectivity:", result.scalar())

        tables = connection.execute(
            text(r"""
                SELECT table_name
                FROM user_tables
                WHERE table_name LIKE 'TV\_%' ESCAPE '\'
                ORDER BY table_name
            """)
        ).scalars().all()

        print("\nExisting TrustVault tables:")

        if not tables:
            print("No TV_* tables found in this Oracle schema.")

        for table_name in tables:
            print(f"\n{table_name}")

            for column in inspect(connection).get_columns(table_name):
                print(
                    f"  {column['name']}: {column['type']}, "
                    f"nullable={column['nullable']}"
                )
                
                
                
                