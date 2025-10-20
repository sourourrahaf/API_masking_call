import os
from faker import Faker
import psycopg2
from dotenv import load_dotenv

load_dotenv()
fake = Faker()

conn = psycopg2.connect(os.getenv('DATABASE_URL'))
cur = conn.cursor()

POOL_SIZE = 200
numbers = []
for _ in range(POOL_SIZE):
         num = f"+21600{fake.random_number(digits=6):06d}"
         numbers.append((num,))

cur.executemany("""
         INSERT INTO proxy_pool (proxy_number, status) 
         VALUES (%s, 'available') 
         ON CONFLICT (proxy_number) DO NOTHING;
     """, numbers)

conn.commit()

cur.execute("SELECT COUNT(*) FROM proxy_pool WHERE status = 'available';")
inserted = cur.fetchone()[0]
print(f"Pool rempli ! {inserted} numéros disponibles insérés (total possible {POOL_SIZE}).")

cur.close()
conn.close()
     