#!/bin/bash

# Função para aguardar o PostgreSQL
echo "Aguardando PostgreSQL em matrix-db:5432..."
until pg_isready -h db -U ${POSTGRES_USER} -d ${POSTGRES_DB}; do
  sleep 1
done

# Função para aguardar o Neo4j (Porta Bolt 7687)
echo "Aguardando Neo4j em matrix-graph:7687..."
until timeout 1s bash -c '< /dev/tcp/neo4j/7687' 2>/dev/null; do
  sleep 1
done

echo "Bancos de dados prontos! Iniciando migrações..."

# Executa migrações do Django
python manage.py migrate --noinput
python manage.py collectstatic --noinput


# Inicia o servidor (ou o worker, dependendo do comando no compose)
exec "$@"
