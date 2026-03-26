#!/usr/bin/env bash
# Migration management for minio_manager_service.
#
# Usage (inside the mms container):
#   docker exec -it <container> bash
#   ./scripts/migrate.sh status      # show current migration version
#   ./scripts/migrate.sh history     # show all migrations
#   ./scripts/migrate.sh up          # migrate to latest (head)
#   ./scripts/migrate.sh up1         # migrate up one revision
#   ./scripts/migrate.sh down1       # migrate down one revision
#   ./scripts/migrate.sh down-all    # migrate down to base (WARNING: destructive)
set -euo pipefail

cd "$(dirname "$0")/.."

ALEMBIC="uv run alembic"

case "${1:-help}" in
  up)        $ALEMBIC upgrade head ;;
  up1)       $ALEMBIC upgrade +1 ;;
  down1)     $ALEMBIC downgrade -1 ;;
  down-all)
    echo "WARNING: This will revert ALL migrations. All tables managed by Alembic will be dropped."
    read -r -p "Type 'yes' to continue: " confirm
    [ "$confirm" = "yes" ] || { echo "Aborted."; exit 1; }
    $ALEMBIC downgrade base
    ;;
  status)    $ALEMBIC current ;;
  history)   $ALEMBIC history --verbose ;;
  help|--help|-h|"")
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  up         Migrate to latest version (head)"
    echo "  up1        Migrate up one revision"
    echo "  down1      Migrate down one revision"
    echo "  down-all   Revert ALL migrations (destructive, requires confirmation)"
    echo "  status     Show current migration version"
    echo "  history    Show migration history"
    echo "  help       Show this message"
    echo ""
    echo "These are thin wrappers around 'alembic' CLI commands."
    echo "For advanced usage, run: uv run alembic --help"
    ;;
  *)
    echo "Unknown command: $1"
    echo "Run '$0 help' for usage."
    exit 1
    ;;
esac
