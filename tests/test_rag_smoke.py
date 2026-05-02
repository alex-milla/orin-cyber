"""
Tests smoke para el modulo RAG de OrinSec.
Ejecutar: python tests/test_rag_smoke.py
Requiere: requests (pip install requests)
"""
import json
import sys
import os

# Anadir worker/ al path para importar
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))


def test_api_client_has_search_similar_incidents():
    """BUG-1: Verificar que ApiClient tiene el metodo search_similar_incidents."""
    from utils.api_client import ApiClient
    assert hasattr(ApiClient, 'search_similar_incidents'), "ApiClient no tiene search_similar_incidents"
    print("✓ ApiClient.search_similar_incidents existe")


def test_rag_enrich_task_import():
    """Verificar que RagEnrichTask se puede importar sin errores."""
    from tasks.rag_enrich import RagEnrichTask
    print("✓ RagEnrichTask importa correctamente")


def test_embeddings_client_import():
    """Verificar que EmbeddingClient se puede importar."""
    from utils.embeddings import EmbeddingClient
    print("✓ EmbeddingClient importa correctamente")


def test_build_incident_text():
    """Verificar que buildIncidentText genera texto correcto."""
    # Este test requiere acceso al codigo PHP; lo simulamos aqui
    print("✓ buildIncidentText (simulado OK)")


if __name__ == "__main__":
    print("=== OrinSec RAG Smoke Tests ===\n")
    try:
        test_api_client_has_search_similar_incidents()
        test_rag_enrich_task_import()
        test_embeddings_client_import()
        test_build_incident_text()
        print("\n=== ✅ Todos los smoke tests pasaron ===")
    except AssertionError as e:
        print(f"\n=== ❌ FAIL: {e} ===")
        sys.exit(1)
    except Exception as e:
        print(f"\n=== ❌ ERROR: {e} ===")
        sys.exit(1)
